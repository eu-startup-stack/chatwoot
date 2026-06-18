# frozen_string_literal: true

require 'ipaddr'

module Authentik
  module ProxyAuth
    Identity = Struct.new(:username, :email, :name, :groups, keyword_init: true)

    GROUP_PREFIX = 'chatwoot-'

    module_function

    def enabled?
      ENV.fetch('AUTHENTIK_ENABLED', '').to_s.downcase == 'true'
    end

    def trusted_ips
      ENV.fetch('AUTHENTIK_TRUSTED_IPS', '').split(',').map(&:strip).reject(&:blank?)
    end

    def trusted_secret
      ENV.fetch('AUTHENTIK_TRUSTED_SECRET', nil)
    end

    def trusted_request?(request)
      ip_allowed?(request) || secret_allowed?(request)
    end

    def identity_from_request(request)
      return nil unless enabled? && trusted_request?(request)

      username = request.headers['X-Authentik-Username']
      email = request.headers['X-Authentik-Email']&.to_s&.downcase&.strip
      name = request.headers['X-Authentik-Name']
      groups = request.headers['X-Authentik-Groups'].to_s.split('|').map(&:strip).reject(&:blank?)

      return nil if username.blank? || email.blank?

      Identity.new(username: username, email: email, name: name, groups: groups)
    end

    def role_from_groups(groups)
      prefixed = (groups || []).filter_map { |g| g.to_s.delete_prefix(GROUP_PREFIX) if g.to_s.start_with?(GROUP_PREFIX) }
      return nil if prefixed.empty?

      return 'administrator' if prefixed.any? { |name| name.downcase == 'admin' || name.downcase == 'administrator' }

      'agent'
    end

    def find_or_create_user!(identity)
      user = User.from_email(identity.email)
      return user if user

      random_password = "#{SecureRandom.hex(16)}aA1!"
      User.transaction do
        user = User.new(
          email: identity.email,
          name: identity.name.presence || identity.username,
          password: random_password,
          password_confirmation: random_password
        )
        user.skip_confirmation!
        user.save!
        user
      end
    end

    def ensure_account_membership!(user, role)
      account = default_account
      raise 'Authentik: no account available for membership' if account.nil?

      account_user = AccountUser.find_by(account_id: account.id, user_id: user.id)
      if account_user
        account_user.update!(role: role) if account_user.role != role
      else
        account_user = AccountUser.create!(account_id: account.id, user_id: user.id, role: role)
      end
      account_user
    end

    def default_account
      if (id = ENV.fetch('AUTHENTIK_DEFAULT_ACCOUNT_ID', nil)).present?
        return Account.find_by(id: id)
      end

      Account.active.order(:id).first
    end

    def ip_allowed?(request)
      list = trusted_ips
      return false if list.empty?

      # Use the immediate TCP peer (REMOTE_ADDR) rather than `request.remote_ip`:
      # `ActionDispatch::RemoteIp` may resolve `remote_ip` to the original client
      # via X-Forwarded-For, which would never match the Authentik outpost's IP.
      remote_ip = request.env['REMOTE_ADDR'].to_s
      list.any? { |entry| ip_match?(remote_ip, entry) }
    end

    def secret_allowed?(request)
      secret = trusted_secret
      return false if secret.blank?

      ActiveSupport::SecurityUtils.secure_compare(request.headers['X-Authentik-Trusted-Secret'].to_s, secret.to_s)
    end

    def ip_match?(ip, entry)
      return false if ip.blank? || entry.blank?

      return ip == entry unless entry.include?('/')

      IPAddr.new(entry).include?(IPAddr.new(ip))
    rescue IPAddr::Error
      false
    end
  end
end
