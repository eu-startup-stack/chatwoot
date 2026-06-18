# frozen_string_literal: true

module Authentik
  class Middleware
    def initialize(app)
      @app = app
    end

    def call(env)
      strip_authentik_headers!(env) if Authentik::ProxyAuth.enabled? && !trusted_env?(env)
      @app.call(env)
    end

    private

    def trusted_env?(env)
      secret = Authentik::ProxyAuth.trusted_secret
      return true if secret.present? &&
                     ActiveSupport::SecurityUtils.secure_compare(
                       env['HTTP_X_AUTHENTIK_TRUSTED_SECRET'].to_s, secret.to_s
                     )

      list = Authentik::ProxyAuth.trusted_ips
      return false if list.empty?

      # Use REMOTE_ADDR (the immediate TCP peer) for trust checks. Even though
      # `action_dispatch.remote_ip` is already populated by `RemoteIp` (which
      # runs before us since we are inserted after it), it resolves to the
      # forwarded client IP via X-Forwarded-For, not the proxy itself.
      remote_ip = env['REMOTE_ADDR'].to_s
      return false if remote_ip.blank?

      list.any? { |entry| Authentik::ProxyAuth.ip_match?(remote_ip, entry) }
    end

    def strip_authentik_headers!(env)
      env.keys.each { |k| env.delete(k) if k.is_a?(String) && k.start_with?('HTTP_X_AUTHENTIK_') }
    end
  end
end
