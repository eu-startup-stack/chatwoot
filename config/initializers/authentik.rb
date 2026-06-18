# frozen_string_literal: true

if Authentik::ProxyAuth.enabled?
  Rails.application.config.middleware.insert_after ActionDispatch::RemoteIp, Authentik::Middleware
end
