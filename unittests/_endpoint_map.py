from esv_reference_server.types import EndpointInfo

# This is purely used for testing purposes and keeps tha code DRY instead of having multiple
# locations where the url, http method, authentication requirement needs to be updated.
# This was previously auto-generated on server startup to avoid needing to separately maintain this
# record but a decision was made for this data structure to be more explicit.
ENDPOINT_MAP = {'ping': EndpointInfo(http_method='GET', url='http://127.0.0.1:52462/', auth_required=False),
                'get_endpoints_data': EndpointInfo(http_method='GET', url='http://127.0.0.1:52462/api/v1/endpoints', auth_required=False),

                # Payment Channel APIs
                'get_account': EndpointInfo(http_method='GET', url='http://127.0.0.1:52462/api/v1/account', auth_required=True),
                'post_account_key': EndpointInfo(http_method='POST', url='http://127.0.0.1:52462/api/v1/account/key', auth_required=True),
                'post_account_channel': EndpointInfo(http_method='POST', url='http://127.0.0.1:52462/api/v1/account/channel', auth_required=True),
                'put_account_channel_update': EndpointInfo(http_method='PUT', url='http://127.0.0.1:52462/api/v1/account/channel', auth_required=True),
                'delete_account_channel': EndpointInfo(http_method='DELETE', url='http://127.0.0.1:52462/api/v1/account/channel', auth_required=True),
                'post_account_funding': EndpointInfo(http_method='POST', url='http://127.0.0.1:52462/api/v1/account/funding', auth_required=True),

                # Peer Channel APIs
                'list_channels': EndpointInfo(http_method='GET', url='http://127.0.0.1:52462/api/v1/channel/manage/list', auth_required=True),
                'get_single_channel_details': EndpointInfo(http_method='GET', url='http://127.0.0.1:52462/api/v1/channel/manage/{channelid}', auth_required=True),
                'update_single_channel_properties': EndpointInfo(http_method='POST', url='http://127.0.0.1:52462/api/v1/channel/manage/{channelid}', auth_required=True),
                'delete_channel': EndpointInfo(http_method='DELETE', url='http://127.0.0.1:52462/api/v1/channel/manage/{channelid}', auth_required=True),
                'create_new_channel': EndpointInfo(http_method='POST', url='http://127.0.0.1:52462/api/v1/channel/manage', auth_required=True),
                'get_token_details': EndpointInfo(http_method='GET', url='http://127.0.0.1:52462/api/v1/channel/manage/{channelid}/api-token/{tokenid}', auth_required=True),
                'revoke_selected_token': EndpointInfo(http_method='DELETE', url='http://127.0.0.1:52462/api/v1/channel/manage/{channelid}/api-token/{tokenid}', auth_required=True),
                'get_list_of_tokens': EndpointInfo(http_method='GET', url='http://127.0.0.1:52462/api/v1/channel/manage/{channelid}/api-token', auth_required=True),
                'create_new_token_for_channel': EndpointInfo(http_method='POST', url='http://127.0.0.1:52462/api/v1/channel/manage/{channelid}/api-token', auth_required=True),
                'write_message': EndpointInfo(http_method='POST', url='http://127.0.0.1:52462/api/v1/channel/{channelid}', auth_required=True),
                'get_messages': EndpointInfo(http_method='GET', url='http://127.0.0.1:52462/api/v1/channel/{channelid}', auth_required=True),
                'mark_message_read_or_unread': EndpointInfo(http_method='POST', url='http://127.0.0.1:52462/api/v1/channel/{channelid}/{sequence}', auth_required=True),
                'delete_message': EndpointInfo(http_method='DELETE', url='http://127.0.0.1:52462/api/v1/channel/{channelid}/{sequence}', auth_required=True),
                'MsgBoxWebSocket': EndpointInfo(http_method='*', url='http://127.0.0.1:52462/api/v1/channel/{channelid}/notify', auth_required=True),

                # General-Purpose Websocket
                'GeneralWebSocket': EndpointInfo(http_method='*', url='http://127.0.0.1:52462/api/v1/web-socket', auth_required=True),

                # HeaderSV APIs
                'HeadersWebSocket': EndpointInfo(http_method='*', url='http://127.0.0.1:52462/api/v1/headers/tips/websocket', auth_required=False),
                'get_chain_tips': EndpointInfo(http_method='GET', url='http://127.0.0.1:52462/api/v1/headers/tips', auth_required=False),
                'get_headers_by_height': EndpointInfo(http_method='GET', url='http://127.0.0.1:52462/api/v1/headers/by-height', auth_required=True),
                'get_header': EndpointInfo(http_method='GET', url='http://127.0.0.1:52462/api/v1/headers/{hash}', auth_required=False),
                'get_peers': EndpointInfo(http_method='GET', url='http://127.0.0.1:52462/api/v1/network/peers', auth_required=False)}
