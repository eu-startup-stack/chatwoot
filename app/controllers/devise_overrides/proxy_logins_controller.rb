# frozen_string_literal: true

class DeviseOverrides::ProxyLoginsController < DeviseOverrides::SessionsController
  skip_before_action :process_sso_auth_token, only: [:create]

  def create
    return render_not_found unless Authentik::ProxyAuth.enabled?

    identity = Authentik::ProxyAuth.identity_from_request(request)
    return render_unauthorized('Authentik proxy authentication required') unless identity

    role = Authentik::ProxyAuth.role_from_groups(identity.groups)
    return render_forbidden('No chatwoot- role group found') unless role

    @resource = Authentik::ProxyAuth.find_or_create_user!(identity)
    Authentik::ProxyAuth.ensure_account_membership!(@resource, role)

    @token = @resource.create_token
    @resource.save!
    sign_in(:user, @resource, store: false, bypass: false)
    render_create_success
  end

  private

  def render_not_found
    render json: { success: false, message: 'Authentik proxy login is not enabled' }, status: :not_found
  end

  def render_unauthorized(message)
    render json: { success: false, message: message }, status: :unauthorized
  end

  def render_forbidden(message)
    render json: { success: false, message: message }, status: :forbidden
  end
end

DeviseOverrides::ProxyLoginsController.prepend_mod_with('DeviseOverrides::ProxyLoginsController')
