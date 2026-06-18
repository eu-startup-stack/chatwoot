# frozen_string_literal: true

require 'spec_helper'
require 'active_support/core_ext/object/blank'
require 'active_support/security_utils'
require_relative '../../../lib/authentik/proxy_auth'
require_relative '../../../lib/authentik/middleware'

RSpec.describe Authentik::ProxyAuth do
  describe '.enabled?' do
    it 'is true when AUTHENTIK_ENABLED is true' do
      with_modified_env AUTHENTIK_ENABLED: 'true', AUTHENTIK_TRUSTED_IPS: nil, AUTHENTIK_TRUSTED_SECRET: nil do
        expect(described_class.enabled?).to be true
      end
    end

    it 'is false when AUTHENTIK_ENABLED is false' do
      with_modified_env AUTHENTIK_ENABLED: 'false', AUTHENTIK_TRUSTED_IPS: nil, AUTHENTIK_TRUSTED_SECRET: nil do
        expect(described_class.enabled?).to be false
      end
    end

    it 'is false when AUTHENTIK_ENABLED is unset' do
      with_modified_env AUTHENTIK_ENABLED: nil, AUTHENTIK_TRUSTED_IPS: nil, AUTHENTIK_TRUSTED_SECRET: nil do
        expect(described_class.enabled?).to be false
      end
    end
  end

  describe '.trusted_request?' do
    it 'is true when remote_ip matches a plain trusted IP' do
      with_modified_env AUTHENTIK_TRUSTED_IPS: '10.0.0.1', AUTHENTIK_TRUSTED_SECRET: nil do
        expect(described_class.trusted_request?(build_request_double(remote_ip: '10.0.0.1'))).to be true
      end
    end

    it 'is true when remote_ip matches a trusted CIDR' do
      with_modified_env AUTHENTIK_TRUSTED_IPS: '10.0.0.0/24', AUTHENTIK_TRUSTED_SECRET: nil do
        expect(described_class.trusted_request?(build_request_double(remote_ip: '10.0.0.42'))).to be true
      end
    end

    it 'is true when X-Authentik-Trusted-Secret matches AUTHENTIK_TRUSTED_SECRET' do
      with_modified_env AUTHENTIK_TRUSTED_IPS: nil, AUTHENTIK_TRUSTED_SECRET: 's3cr3t' do
        request = build_request_double(headers: { 'X-Authentik-Trusted-Secret' => 's3cr3t' })
        expect(described_class.trusted_request?(request)).to be true
      end
    end

    it 'is false when neither IPs nor secret are configured' do
      with_modified_env AUTHENTIK_TRUSTED_IPS: nil, AUTHENTIK_TRUSTED_SECRET: nil do
        expect(described_class.trusted_request?(build_request_double(remote_ip: '1.2.3.4'))).to be false
      end
    end

    it 'is false when remote_ip is not in the trusted list and no secret is set' do
      with_modified_env AUTHENTIK_TRUSTED_IPS: '10.0.0.1', AUTHENTIK_TRUSTED_SECRET: nil do
        expect(described_class.trusted_request?(build_request_double(remote_ip: '1.2.3.4'))).to be false
      end
    end

    it 'is false when secret is wrong' do
      with_modified_env AUTHENTIK_TRUSTED_IPS: nil, AUTHENTIK_TRUSTED_SECRET: 'right' do
        request = build_request_double(headers: { 'X-Authentik-Trusted-Secret' => 'wrong' })
        expect(described_class.trusted_request?(request)).to be false
      end
    end

    it 'is false when secret is absent' do
      with_modified_env AUTHENTIK_TRUSTED_IPS: nil, AUTHENTIK_TRUSTED_SECRET: 'right' do
        expect(described_class.trusted_request?(build_request_double)).to be false
      end
    end

    it 'treats an invalid CIDR entry as a non-match rather than raising' do
      with_modified_env AUTHENTIK_TRUSTED_IPS: 'not-a-cidr', AUTHENTIK_TRUSTED_SECRET: nil do
        expect(described_class.trusted_request?(build_request_double(remote_ip: '10.0.0.1'))).to be false
      end
    end
  end

  describe '.identity_from_request' do
    let(:headers) do
      {
        'X-Authentik-Username' => 'alice',
        'X-Authentik-Email' => 'Alice@Example.com',
        'X-Authentik-Name' => 'Alice Example',
        'X-Authentik-Groups' => 'users|chatwoot-admin|admins'
      }
    end

    it 'returns a parsed Identity when enabled and trusted' do
      with_modified_env AUTHENTIK_ENABLED: 'true', AUTHENTIK_TRUSTED_IPS: '10.0.0.1', AUTHENTIK_TRUSTED_SECRET: nil do
        request = build_request_double(remote_ip: '10.0.0.1', headers: headers)
        identity = described_class.identity_from_request(request)
        expect(identity).not_to be_nil
        expect(identity.username).to eq 'alice'
        expect(identity.email).to eq 'alice@example.com'
        expect(identity.name).to eq 'Alice Example'
        expect(identity.groups).to eq %w[users chatwoot-admin admins]
      end
    end

    it 'returns nil when disabled' do
      with_modified_env AUTHENTIK_ENABLED: 'false', AUTHENTIK_TRUSTED_IPS: '10.0.0.1', AUTHENTIK_TRUSTED_SECRET: nil do
        request = build_request_double(remote_ip: '10.0.0.1', headers: headers)
        expect(described_class.identity_from_request(request)).to be_nil
      end
    end

    it 'returns nil when not trusted' do
      with_modified_env AUTHENTIK_ENABLED: 'true', AUTHENTIK_TRUSTED_IPS: '10.0.0.1', AUTHENTIK_TRUSTED_SECRET: nil do
        request = build_request_double(remote_ip: '1.2.3.4', headers: headers)
        expect(described_class.identity_from_request(request)).to be_nil
      end
    end

    it 'returns nil when username is blank' do
      with_modified_env AUTHENTIK_ENABLED: 'true', AUTHENTIK_TRUSTED_IPS: '10.0.0.1', AUTHENTIK_TRUSTED_SECRET: nil do
        bad_headers = headers.merge('X-Authentik-Username' => '')
        request = build_request_double(remote_ip: '10.0.0.1', headers: bad_headers)
        expect(described_class.identity_from_request(request)).to be_nil
      end
    end

    it 'returns nil when email is blank' do
      with_modified_env AUTHENTIK_ENABLED: 'true', AUTHENTIK_TRUSTED_IPS: '10.0.0.1', AUTHENTIK_TRUSTED_SECRET: nil do
        bad_headers = headers.merge('X-Authentik-Email' => '')
        request = build_request_double(remote_ip: '10.0.0.1', headers: bad_headers)
        expect(described_class.identity_from_request(request)).to be_nil
      end
    end

    it 'splits groups on pipe and strips whitespace, dropping blanks' do
      with_modified_env AUTHENTIK_ENABLED: 'true', AUTHENTIK_TRUSTED_IPS: '10.0.0.1', AUTHENTIK_TRUSTED_SECRET: nil do
        weird_headers = headers.merge('X-Authentik-Groups' => ' users |  chatwoot-admin  || admins |')
        request = build_request_double(remote_ip: '10.0.0.1', headers: weird_headers)
        identity = described_class.identity_from_request(request)
        expect(identity.groups).to eq %w[users chatwoot-admin admins]
      end
    end
  end

  describe '.role_from_groups' do
    it 'returns administrator for chatwoot-admin' do
      expect(described_class.role_from_groups(['chatwoot-admin'])).to eq 'administrator'
    end

    it 'returns administrator for chatwoot-administrator' do
      expect(described_class.role_from_groups(['chatwoot-administrator'])).to eq 'administrator'
    end

    it 'returns administrator when admin and agent groups are both present' do
      expect(described_class.role_from_groups(%w[chatwoot-agent chatwoot-admin])).to eq 'administrator'
    end

    it 'returns agent for chatwoot-agent only' do
      expect(described_class.role_from_groups(['chatwoot-agent'])).to eq 'agent'
    end

    it 'returns agent for any other chatwoot- prefixed group' do
      expect(described_class.role_from_groups(['chatwoot-supervisor'])).to eq 'agent'
    end

    it 'ignores non chatwoot- groups' do
      expect(described_class.role_from_groups(%w[users admins])).to be_nil
    end

    it 'returns nil when no chatwoot- prefixed group is present' do
      expect(described_class.role_from_groups([])).to be_nil
    end

    it 'returns nil when groups is nil' do
      expect(described_class.role_from_groups(nil)).to be_nil
    end
  end

  def build_request_double(remote_ip: '127.0.0.1', env: {}, headers: {})
    double('request', remote_ip: remote_ip, env: env.merge('REMOTE_ADDR' => remote_ip), headers: headers)
  end
end

RSpec.describe Authentik::Middleware do
  let(:inner_app) { ->(_env) { [200, {}, ['ok']] } }
  let(:middleware) { described_class.new(inner_app) }

  def call(env)
    middleware.call(env)
  end

  it 'strips HTTP_X_AUTHENTIK_* env keys from untrusted requests when enabled' do
    env = {
      'REMOTE_ADDR' => '1.2.3.4',
      'HTTP_X_AUTHENTIK_USERNAME' => 'mallory',
      'HTTP_X_AUTHENTIK_EMAIL' => 'mallory@example.com',
      'HTTP_X_AUTHENTIK_GROUPS' => 'chatwoot-admin'
    }
    with_modified_env AUTHENTIK_ENABLED: 'true', AUTHENTIK_TRUSTED_IPS: '10.0.0.1', AUTHENTIK_TRUSTED_SECRET: nil do
      call(env)
      expect(env).not_to have_key('HTTP_X_AUTHENTIK_USERNAME')
      expect(env).not_to have_key('HTTP_X_AUTHENTIK_EMAIL')
      expect(env).not_to have_key('HTTP_X_AUTHENTIK_GROUPS')
    end
  end

  it 'preserves X-Authentik-* headers when source IP is in AUTHENTIK_TRUSTED_IPS' do
    env = {
      'REMOTE_ADDR' => '10.0.0.1',
      'HTTP_X_AUTHENTIK_USERNAME' => 'alice',
      'HTTP_X_AUTHENTIK_EMAIL' => 'alice@example.com'
    }
    with_modified_env AUTHENTIK_ENABLED: 'true', AUTHENTIK_TRUSTED_IPS: '10.0.0.1', AUTHENTIK_TRUSTED_SECRET: nil do
      call(env)
      expect(env['HTTP_X_AUTHENTIK_USERNAME']).to eq 'alice'
      expect(env['HTTP_X_AUTHENTIK_EMAIL']).to eq 'alice@example.com'
    end
  end

  it 'preserves X-Authentik-* headers when X-Authentik-Trusted-Secret matches' do
    env = {
      'REMOTE_ADDR' => '1.2.3.4',
      'HTTP_X_AUTHENTIK_TRUSTED_SECRET' => 's3cr3t',
      'HTTP_X_AUTHENTIK_USERNAME' => 'alice'
    }
    with_modified_env AUTHENTIK_ENABLED: 'true', AUTHENTIK_TRUSTED_IPS: nil, AUTHENTIK_TRUSTED_SECRET: 's3cr3t' do
      call(env)
      expect(env['HTTP_X_AUTHENTIK_USERNAME']).to eq 'alice'
      expect(env['HTTP_X_AUTHENTIK_TRUSTED_SECRET']).to eq 's3cr3t'
    end
  end

  it 'is a no-op when Authentik is disabled' do
    env = {
      'REMOTE_ADDR' => '1.2.3.4',
      'HTTP_X_AUTHENTIK_USERNAME' => 'mallory'
    }
    with_modified_env AUTHENTIK_ENABLED: 'false', AUTHENTIK_TRUSTED_IPS: nil, AUTHENTIK_TRUSTED_SECRET: nil do
      call(env)
      expect(env['HTTP_X_AUTHENTIK_USERNAME']).to eq 'mallory'
    end
  end

  it 'always passes through to the inner app' do
    env = { 'REMOTE_ADDR' => '1.2.3.4' }
    expect(inner_app).to receive(:call).with(env).and_return([200, {}, ['ok']])
    with_modified_env AUTHENTIK_ENABLED: 'true', AUTHENTIK_TRUSTED_IPS: nil, AUTHENTIK_TRUSTED_SECRET: nil do
      expect(call(env)).to eq [200, {}, ['ok']]
    end
  end
end
