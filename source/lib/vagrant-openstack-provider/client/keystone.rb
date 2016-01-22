require 'log4r'
require 'json'

require 'vagrant-openstack-provider/client/request_logger'

module VagrantPlugins
  module Openstack
    class KeystoneClientV2
      include Singleton
      include VagrantPlugins::Openstack::HttpUtils::RequestLogger

      def initialize
        @logger = Log4r::Logger.new('vagrant_openstack::keystone::v2')
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
        auth_url = get_auth_url env
        log_request(:POST, auth_url, post_body.to_json, headers)
        post_body[:auth][:passwordCredentials][:password] = config.password

        authentication = post(env, auth_url, post_body, headers)

        access = JSON.parse(authentication)['access']
        response_token = access['token']
        @session.token = response_token['id']
        @session.project_id = response_token['tenant']['id']
        access['serviceCatalog']
      end

      private

      def get_auth_url(env)
        url = env[:machine].provider_config.openstack_auth_url
        return url if url.match(%r{/tokens/*$})
        "#{url}/tokens"
      end

      def post(env, auth_url, post_body, headers)
        RestUtils.post(env, auth_url, post_body.to_json, headers) do |response|
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
      end
    end

    class KeystoneClientV3 < KeystoneClientV2
      def initialize
        @logger = Log4r::Logger.new('vagrant_openstack::keystone::v3')
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
        auth_url = get_auth_url env
        log_request(:POST, auth_url, post_body.to_json, headers)
        post_body[:auth][:identity][:password][:user][:password] = config.password

        authentication = post(env, auth_url, post_body, headers)

        @session.token = authentication.headers[:x_subject_token]
        token = JSON.parse(authentication)['token']
        @session.project_id = token['project']['id']
        token['catalog']
      end
    end
  end
end
