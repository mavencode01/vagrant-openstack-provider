require 'log4r'
require 'json'

require 'vagrant-openstack-provider/client/request_logger'

module VagrantPlugins
  module Openstack
    class KeystoneClient
      include Singleton
      include VagrantPlugins::Openstack::HttpUtils::RequestLogger

      def initialize
        @logger = Log4r::Logger.new('vagrant_openstack::keystone')
        @session = VagrantPlugins::Openstack.session
      end

      def authenticate(env)
        @logger.info('Authenticating on Keystone')
        config = env[:machine].provider_config
        @logger.info(I18n.t('vagrant_openstack.client.authentication', project: config.tenant_name, user: config.username))

        headers = {
          content_type: :json,
          accept: :json
        }

        case config.openstack_auth_version
        when 'v2','v2.0'
            post_body =
              {
                auth:
                  {
                    tenantName: config.tenant_name,
                    passwordCredentials:
                      {
                        username: config.username,
                        password: '****'
                      }
                  }
              }
            auth_url = get_auth_url_v2 env
            log_request(:POST, auth_url, post_body.to_json, headers)
            post_body[:auth][:passwordCredentials][:password] = config.password

        when 'v3'
            post_body =
              {
                auth:
                  {
                    identity:
                      {
                         methods: ['password'],
                         password:
                           {
                              user:
                                 {
                                    name: config.username,
                                    password: '****',
                                    domain:
                                       {
                                          name: config.domain
                                       }
                                 }
                           }
                      },
                    scope:
                      {
                         project:
                           {
                              name: config.tenant_name,
                              domain:
                                {
                                   name: config.domain
                                }
                           }
                      }
                  }
              }
            auth_url = get_auth_url_v3 env
            log_request(:POST, auth_url, post_body.to_json, headers)
            post_body[:auth][:identity][:password][:user][:password] = config.password
        else
            fail Errors::VagrantOpenstackError, message: 'invalid openstack_auth_version %s' % config.openstack_auth_version
        end

        authentication = RestUtils.post(env, auth_url, post_body.to_json, headers) do |response|
          log_response(response)
          case response.code
          when 200, 201
            response
          when 401
            fail Errors::AuthenticationFailed
          when 404
            fail Errors::BadAuthenticationEndpoint
          else
            fail Errors::VagrantOpenstackError, message: response.to_s
          end
        end

        case config.openstack_auth_version
        when 'v2','v2.0'
            access = JSON.parse(authentication)['access']
            response_token = access['token']
            @session.token = response_token['id']
            @session.project_id = response_token['tenant']['id']
            return access['serviceCatalog']
        when 'v3'
            @session.token = authentication.headers[:x_subject_token]
            token = JSON.parse(authentication)['token']
            @session.project_id = token['project']['id']
            return token['catalog']
        else
            fail Errors::VagrantOpenstackError, message: 'invalid openstack_auth_version'
        end

      end

      private

      def get_auth_url_v2(env)
        url = env[:machine].provider_config.openstack_auth_url
        return url if url.match(%r{/tokens/*$})
        "#{url}/tokens"
      end

      def get_auth_url_v3(env)
        get_auth_url_v2(env)
      end
    end
  end
end
