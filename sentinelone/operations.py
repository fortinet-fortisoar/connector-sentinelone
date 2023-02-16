""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import json, os
from connectors.core.connector import get_logger, ConnectorError
from .utils import (_build_url, _get,
                    _post,
                    _get_headers, logout_user,
                    error_handling)
from .constant import Threats_2_0, Threats_2_1, Threats_Details_2_0, Threats_Details_2_1, Agent_2_0, Agent_2_1, OS_Type, \
    APP_Type_List, Sort_Type, Incident_State_List
from connectors.cyops_utilities.builtins import upload_file_to_cyops
from django.conf import settings

logger = get_logger('sentinelOne')


def convert_int_str(params):
    siteIds = params.get('siteIds')
    groupIds = params.get('groupIds')
    accountIds = params.get('accountIds')
    if siteIds:
        siteIds = str(siteIds).split(",")
        params.update({'siteIds': siteIds})
    if groupIds:
        groupIds = str(groupIds).split(",")
        params.update({'groupIds': groupIds})
    if accountIds:
        accountIds = str(accountIds).split(",")
        params.update({'accountIds': accountIds})
    return params


def get_payload(params):
    payload = {}
    payload.update(params)
    payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    return payload


def create_payload(params):
    payload = {}
    filter = {k: v for k, v in params.items() if v is not None and v != ''}
    ids = params.get('ids')
    if type(ids) == str and ids:
        ids = [x.strip() for x in ids.split(',')]
        ids = list(map(str, ids))
        ids = {'ids': ids}
        filter.update(ids)
    elif type(ids) == int:
        ids = {'ids': str(ids)}
        filter.update(ids)
    payload['filter'] = filter
    payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    return payload


def fetch_agent_logs(config, params):
    headers = _get_headers(config)
    net_list, os_list = [], []
    networkStatuses = params.get('networkStatuses')
    if networkStatuses:
        for net in networkStatuses:
            net_list.append(net.lower())
        params.update({'networkStatuses': ','.join(net_list)})
    osTypes = params.get('osTypes')
    if osTypes:
        for ost in osTypes:
            os_list.append(OS_Type.get(ost))
        params.update({'osTypes': ','.join(os_list)})
    endpoint = 'web/api/{0}/agents/actions/fetch-logs'.format(config.get('api_version'))
    url, verify_ssl = _build_url(config, method_name=endpoint)
    payload = create_payload(params)
    response = _post(headers, url, body=payload, verify=verify_ssl)
    if response.get('data'):
        return response.get('data')
    elif response:
        return response
    error_handling("Failed to fetch agent logs. ", response.text)


def mark_threat_as_benign(config, params):
    headers = _get_headers(config)
    endpoint = 'web/api/{0}/threats/mark-as-benign'.format(config.get('api_version'))
    data = {}
    data['targetScope'] = params.get('targetScope')
    params.pop('targetScope')
    payload = create_payload(params)
    payload['data'] = data
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _post(headers, url, body=payload, verify=verify_ssl)
    if response.get('data'):
        return response.get('data')
    elif response:
        return response
    error_handling("Failed to mark as benign. ", response.text)


def isolate_agent_network(config, params):
    headers = _get_headers(config)
    groupIds = params.get("groupIds")
    if groupIds:
        groupIds = str(groupIds).split(",")
        params.update({'groupIds': groupIds})
    endpoint = 'web/api/{0}/agents/actions/disconnect'.format(config.get('api_version'))
    payload = create_payload(params)
    url, verify_ssl = _build_url(config, method_name=endpoint)
    agent_networks = _post(headers, url, body=payload, verify=verify_ssl)
    logout_user(config, headers)
    if agent_networks.get('data'):
        return agent_networks.get('data')
    elif agent_networks:
        return agent_networks
    error_handling("Failed to disconnect agent network. ", agent_networks.text)


def reconnect_agent(config, params):
    headers = _get_headers(config)
    net_list, os_list = [], []
    networkStatuses = params.get('networkStatuses')
    if networkStatuses:
        for net in networkStatuses:
            net_list.append(net.lower())
        params.update({'networkStatuses': ','.join(net_list)})
    osTypes = params.get('osTypes')
    if osTypes:
        for ost in osTypes:
            os_list.append(OS_Type.get(ost))
        params.update({'osTypes': ','.join(os_list)})
    endpoint = 'web/api/{0}/agents/actions/connect'.format(config.get('api_version'))
    payload = create_payload(params)
    url, verify_ssl = _build_url(config, method_name=endpoint)
    agent_networks = _post(headers, url, body=payload, verify=verify_ssl)
    logout_user(config, headers)
    if agent_networks.get('data'):
        return agent_networks.get('data')
    elif agent_networks:
        return agent_networks
    error_handling("Failed to reconnect agent network. ", agent_networks.text)


def decommission_agent(config, params):
    headers = _get_headers(config)
    endpoint = 'web/api/{0}/agents/actions/decommission'.format(config.get('api_version'))
    groupIds = params.get("groupIds")
    if groupIds:
        groupIds = str(groupIds).split(",")
        params.update({'groupIds': groupIds})
    payload = create_payload(params)
    url, verify_ssl = _build_url(config, method_name=endpoint)
    decommission_agent_status = _post(headers, url, body=payload, verify=verify_ssl)
    logout_user(config, headers)
    if decommission_agent_status.get('data'):
        return decommission_agent_status.get('data')
    elif decommission_agent_status:
        return decommission_agent_status
    error_handling("Failed to decommission agent. ", decommission_agent_status.text)


def uninstall_agent(config, params):
    headers = _get_headers(config)
    endpoint = 'web/api/{0}/agents/actions/uninstall'.format(config.get('api_version'))
    groupIds = params.get("groupIds")
    if groupIds:
        groupIds = str(groupIds).split(",")
        params.update({'groupIds': groupIds})
    payload = create_payload(params)
    url, verify_ssl = _build_url(config, method_name=endpoint)
    agent_uninstall = _post(headers, url, body=payload, verify=verify_ssl)
    logout_user(config, headers)
    if agent_uninstall.get('data'):
        return agent_uninstall.get('data')
    elif agent_uninstall:
        return agent_uninstall
    error_handling("Failed to uninstall agent. ", agent_uninstall.text)


def shutdown_agent(config, params):
    headers = _get_headers(config)
    endpoint = 'web/api/{0}/agents/actions/shutdown'.format(config.get('api_version'))
    groupIds = params.get("groupIds")
    if groupIds:
        groupIds = str(groupIds).split(",")
        params.update({'groupIds': groupIds})
    payload = create_payload(params)
    url, verify_ssl = _build_url(config, method_name=endpoint)
    agent_shutdown = _post(headers, url, body=payload, verify=verify_ssl)
    logout_user(config, headers)
    if agent_shutdown.get('data'):
        return agent_shutdown.get('data')
    elif agent_shutdown:
        return agent_shutdown
    error_handling("Failed to shutdown agent. ", agent_shutdown.text)


def broadcast_message_to_agent(config, params):
    headers = _get_headers(config)
    net_list, os_list = [], []
    networkStatuses = params.get('networkStatuses')
    if networkStatuses:
        for net in networkStatuses:
            net_list.append(net.lower())
        params.update({'networkStatuses': ','.join(net_list)})
    osTypes = params.get('osTypes')
    if osTypes:
        for ost in osTypes:
            os_list.append(OS_Type.get(ost))
        params.update({'osTypes': ','.join(os_list)})
    endpoint = 'web/api/{0}/agents/actions/broadcast'.format(config.get('api_version'))
    data = {}
    data['message'] = params.get('message')
    params.pop('message')
    payload = create_payload(params)
    payload['data'] = data
    url, verify_ssl = _build_url(config, method_name=endpoint)
    agent_broadcast = _post(headers, url, body=payload, verify=verify_ssl)
    if agent_broadcast.get('data'):
        return agent_broadcast.get('data')
    elif agent_broadcast:
        return agent_broadcast
    error_handling("Failed to broadcast message to agent. ", agent_broadcast.text)


def initiate_agent_scan(config, params):
    headers = _get_headers(config)
    endpoint = 'web/api/{0}/agents/actions/initiate-scan'.format(config.get('api_version'))
    extra_parameters = params.get('extra_parameters')
    if extra_parameters:
        params.pop('extra_parameters')
        params.update(extra_parameters)
    payload = create_payload(params)
    url, verify_ssl = _build_url(config, method_name=endpoint)
    initiate_scan = _post(headers, url, body=payload, verify=verify_ssl)
    logout_user(config, headers)
    if initiate_scan.get('data'):
        return initiate_scan.get('data')
    elif initiate_scan:
        return initiate_scan
    error_handling("Failed to initiate scan for agent. ", initiate_scan.text)


def abort_agent_scan(config, params):
    headers = _get_headers(config)
    net_list, os_list = [], []
    networkStatuses = params.get('networkStatuses')
    if networkStatuses:
        for net in networkStatuses:
            net_list.append(net.lower())
        params.update({'networkStatuses': ','.join(net_list)})
    osTypes = params.get('osTypes')
    if osTypes:
        for ost in osTypes:
            os_list.append(OS_Type.get(ost))
        params.update({'osTypes': ','.join(os_list)})
    extra_parameters = params.get('extra_parameters')
    if extra_parameters:
        params.pop('extra_parameters')
        params.update(extra_parameters)
    endpoint = 'web/api/{0}/agents/actions/abort-scan'.format(config.get('api_version'))
    payload = create_payload(params)
    url, verify_ssl = _build_url(config, method_name=endpoint)
    abort_scan = _post(headers, url, body=payload, verify=verify_ssl)
    logout_user(config, headers)
    if abort_scan.get('data'):
        return abort_scan.get('data')
    elif abort_scan:
        return abort_scan
    error_handling("Failed to abort scan for agent. ", abort_scan.text)


def mitigate_threats(config, params):
    headers = _get_headers(config)
    endpoint = 'web/api/{0}/threats/mitigate/{1}'.format(config.get('api_version'), params.get('action').lower())
    params.pop('action')
    payload = create_payload(params)
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _post(headers, url, body=payload, verify=verify_ssl)
    if response.get('data'):
        return response.get('data')
    elif response:
        return response
    error_handling("Failed to mitigate threats. ", response.text)


def _agent_action_mapping(action):
    mapper = {
        'Isolate Agent Network': isolate_agent_network,
        'Decommission Agent': decommission_agent,
        'Uninstall Agent': uninstall_agent,
        'Shutdown Agent': shutdown_agent
    }
    return mapper.get(action)


def agent_action(config, params):
    execute = _agent_action_mapping(params.get('action'))
    params.pop('action')
    if execute:
        return execute(config, params)


def create_query(config, params):
    headers = _get_headers(config)
    endpoint = "web/api/{0}/dv/init-query".format(config.get('api_version'))
    type = params.get('queryType')
    account_ids = params.get('accountIds')
    site_ids = params.get('siteIds')
    group_ids = params.get('groupIds')
    if type:
        type = list(type.split(","))
    if account_ids:
        account_ids = str(account_ids.split(","))
    if site_ids:
        site_ids = str(site_ids.split(","))
    if group_ids:
        group_ids = str(group_ids.split(","))
    payload = {
        "fromDate": params.get('fromDate'),
        "groupIds": group_ids,
        "tenant": params.get('tenant'),
        "query": params.get('query'),
        "toDate": params.get('toDate'),
        "queryType": type,
        "accountIds": account_ids,
        "siteIds": site_ids
    }
    payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _post(headers, url, body=payload, verify=verify_ssl)
    if response.get('data'):
        return response.get('data')
    elif response:
        return response
    error_handling("Failed to Create Query. ", response.text)


def get_query_status(config, params):
    headers = _get_headers(config)
    endpoint = 'web/api/{0}/dv/query-status'.format(config.get('api_version'))
    payload = {
        "queryId": params.get('queryId')
    }
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _get(headers, url, params=payload, verify=verify_ssl)
    if response.get('data'):
        return response.get('data')
    elif response:
        return response
    error_handling("Failed to get query status. ", response.text)


def get_events(config, params):
    headers = _get_headers(config)
    endpoint = 'web/api/{0}/dv/events'.format(config.get('api_version'))
    sortOrder = params.get('sortOrder')
    if sortOrder:
        sortOrder = {'sortOrder': Sort_Type.get(sortOrder)}
        params.update(sortOrder)
    payload = get_payload(params)
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _get(headers, url, params=payload, verify=verify_ssl)
    if response:
        return response
    error_handling("Failed to get events. ", response.text)


def get_events_by_type(config, params):
    headers = _get_headers(config)
    endpoint = 'web/api/{0}/dv/events/{1}'.format(config.get('api_version'), params.get('event_type').lower())
    sortOrder = params.get('sortOrder')
    if sortOrder:
        sortOrder = {'sortOrder': Sort_Type.get(sortOrder)}
        params.update(sortOrder)
    payload = get_payload(params)
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _get(headers, url, params=payload, verify=verify_ssl)
    if response:
        return response
    error_handling("Failed to get events by type. ", response.text)


def cancel_running_query(config, params):
    headers = _get_headers(config)
    endpoint = 'web/api/{0}/dv/cancel-query'.format(config.get('api_version'))
    payload = {
        "queryId": params.get('queryId')
    }
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _post(headers, url, body=payload, verify=verify_ssl)
    if response:
        return response
    error_handling("Failed to cancel running query. ", response.text)


def threat_seen_on_network(config, params):
    headers = _get_headers(config)
    endpoint = 'web/api/{0}/threats/{1}/forensics/seenOnNetwork'.format(config.get('api_version'),
                                                                        params.get('threat_id'))
    payload = get_payload(params)
    payload.pop('threat_id')
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _get(headers, url, params=payload, verify=verify_ssl)
    if response.get('data'):
        return response.get('data')
    elif response:
        return response
    error_handling("Failed to threat seen on network. ", response.text)


def threat_forensic_details(config, params):
    headers = _get_headers(config)
    threat_id = params.get('threat_id')
    endpoint = 'web/api/{0}/threats/{1}/forensics/details'.format(config.get('api_version'), threat_id)
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _get(headers, url, verify=verify_ssl)
    if response.get('data'):
        return response.get('data')
    elif response:
        return response
    error_handling("Failed to get forensics threat details. ", response.text)


def export_forensics_threat(config, params):
    headers = _get_headers(config)
    export_format = params.get('export_format')
    threat_id = params.get('threat_id')
    endpoint = 'web/api/{0}/threats/{1}/forensics/export/{2}'.format(config.get('api_version'), threat_id,
                                                                     export_format.lower())
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _get(headers, url, verify=verify_ssl)
    try:
        if response:
            if export_format == 'JSON' or export_format == 'RAW':
                return response
            else:
                res = response.text.split("\r\n")
                return res
        elif response == []:
            return response
    except:
        if response:
            return response
    error_handling("Failed to export forensics threat. ", response.text)


def threat_forensics(config, params):
    headers = _get_headers(config)
    endpoint = 'web/api/{0}/threats/{1}/forensics'.format(config.get('api_version'), params.get('threat_id'))
    payload = get_payload(params)
    url, verify_ssl = _build_url(config, method_name=endpoint)
    payload.pop('threat_id')
    response = _get(headers, url, params=payload, verify=verify_ssl)
    if response.get('data'):
        return response.get('data')
    elif response:
        return response
    error_handling("Failed to threat forensics. ", response.text)


def free_text_filters(config, params):
    headers = _get_headers(config)
    endpoint = 'web/api/{0}/private/installed-applications/free-text-filters'.format(config.get('api_version'))
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _get(headers, url, verify=verify_ssl)
    if response.get('data'):
        return response.get('data')
    elif response:
        return response
    error_handling("Failed to get free text filters. ", response.text)


def get_application_count(config, params):
    headers = _get_headers(config)
    mac_list, type_list, risk_list, os_list = [], [], [], []
    base_url = 'web/api/{0}/private/installed-applications'.format(config.get('api_version'))
    agentMachineTypes = params.get('agentMachineTypes')
    if agentMachineTypes:
        for mach in agentMachineTypes:
            mac_list.append(mach.lower())
        agentMachineTypes = ','.join(mac_list)
    types = params.get('types')
    if types:
        for type in types:
            type_list.append(APP_Type_List.get(type))
        types = ','.join(type_list)
    riskLevels = params.get('riskLevels')
    if riskLevels:
        for res in riskLevels:
            risk_list.append(res.lower())
        riskLevels = ','.join(risk_list)
    osTypes = params.get('osTypes')
    if osTypes:
        for ost in osTypes:
            os_list.append(ost.lower())
        osTypes = ','.join(os_list)
    filterBy = params.get('filterBy')
    if filterBy == 'Risk Levels':
        endpoint = base_url + '/risk-levels-count'
    else:
        endpoint = base_url + '/filters-count'
    payload = {'agentMachineTypes': agentMachineTypes, 'types': types,
               'riskLevels': riskLevels, 'osTypes': osTypes}
    params.update(payload)
    payload = get_payload(params)
    extra_parameters = params.get('extra_parameters')
    if extra_parameters:
        payload.update(extra_parameters)
    payload.pop('filterBy')
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _get(headers, url, params=payload, verify=verify_ssl)
    if response.get('data'):
        return response.get('data')
    elif response:
        return response
    error_handling("Failed to get application count. ", response.text)


def get_cve(config, params):
    headers = _get_headers(config)
    endpoint = 'web/api/{0}/installed-applications/cves'.format(config.get('api_version'))
    sortBy = params.get('sortBy')
    if sortBy:
        if sortBy == 'ID':
            sortBy = 'id'
            params.update({'sortBy': sortBy})
        else:
            sortBy = sortBy[0].lower() + sortBy[1:]
            params.update({'sortBy': sortBy})
    sortOrder = params.get('sortOrder')
    if sortOrder:
        sortOrder = {'sortOrder': Sort_Type.get(sortOrder)}
        params.update(sortOrder)
    extra_parameters = params.get('extra_parameters')
    if extra_parameters:
        params.pop('extra_parameters')
        params.update(extra_parameters)
    ids = params.get('ids')
    if ids and type(ids) == list:
        params.update({'ids': ','.join(map(str, ids))})
    payload = get_payload(params)
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _get(headers, url, params=payload, verify=verify_ssl)
    if response:
        return response
    error_handling("Failed to get cves. ", response.text)


def export_applications_risk(config, params):
    headers = _get_headers(config)
    mac_list, type_list, risk_list, os_list = [], [], [], []
    endpoint = 'web/api/{0}/export/installed-applications'.format(config.get('api_version'))
    agentMachineTypes = params.get('agentMachineTypes')
    if agentMachineTypes:
        for mach in agentMachineTypes:
            mac_list.append(mach.lower())
        agentMachineTypes = ','.join(mac_list)
    types = params.get('types')
    if types:
        for type in types:
            type_list.append(APP_Type_List.get(type))
        types = ','.join(type_list)
    riskLevels = params.get('riskLevels')
    if riskLevels:
        for res in riskLevels:
            risk_list.append(res.lower())
        riskLevels = ','.join(risk_list)
    osTypes = params.get('osTypes')
    if osTypes:
        for ost in osTypes:
            os_list.append(ost.lower())
        osTypes = ','.join(os_list)
    payload = {'agentMachineTypes': agentMachineTypes, 'types': types,
               'riskLevels': riskLevels, 'osTypes': osTypes}
    params.update(payload)
    payload = get_payload(params)
    extra_parameters = params.get('extra_parameters')
    if extra_parameters:
        payload.update(extra_parameters)
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _get(headers, url, params=payload, verify=verify_ssl)
    try:
        if response:
            if response.headers['Content-Disposition']:
                file_name = json.loads(response.headers['Content-Disposition'].split("=")[1])
                path = os.path.join(settings.TMP_FILE_ROOT, file_name)
                logger.debug("Path: {0}".format(path))
                with open(path, 'wb') as fp:
                    fp.write(response.content)
                attach_response = upload_file_to_cyops(file_path=file_name, filename=file_name,
                                                       name=file_name, create_attachment=True)
                return attach_response
            else:
                result = (response.text).split("\r\n")
                return (result)
    except Exception as e:
        raise ConnectorError(e)
    error_handling("Failed to get export applications risk. ", response.text)


def get_applications(config, params):
    headers = _get_headers(config)
    mac_list, type_list, risk_list, os_list = [], [], [], []
    endpoint = 'web/api/{0}/installed-applications'.format(config.get('api_version'))
    agentMachineTypes = params.get('agentMachineTypes')
    if agentMachineTypes:
        for mach in agentMachineTypes:
            mac_list.append(mach.lower())
        agentMachineTypes = ','.join(mac_list)
    types = params.get('types')
    if types:
        for type in types:
            type_list.append(APP_Type_List.get(type))
        types = ','.join(type_list)
    riskLevels = params.get('riskLevels')
    if riskLevels:
        for res in riskLevels:
            risk_list.append(res.lower())
        riskLevels = ','.join(risk_list)
    osTypes = params.get('osTypes')
    if osTypes:
        for ost in osTypes:
            os_list.append(ost.lower())
        osTypes = ','.join(os_list)
    sortBy = params.get('sortBy')
    if sortBy:
        sortBy = sortBy[0].lower() + sortBy[1:]
    sortOrder = params.get('sortOrder')
    if sortOrder:
        sortOrder = Sort_Type.get(sortOrder)
    payload = {'sortOrder': sortOrder, 'agentMachineTypes': agentMachineTypes,
               'types': types,
               'riskLevels': riskLevels, 'sortBy': sortBy,
               'osTypes': osTypes}
    extra_parameters = params.get('extra_parameters')
    if extra_parameters:
        params.pop('extra_parameters')
        params.update(extra_parameters)
    params.update(payload)
    payload = get_payload(params)
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _get(headers, url, params=payload, verify=verify_ssl)
    if response:
        return response
    error_handling("Failed to get applications. ", response.text)


def get_application_cve(config, params):
    headers = _get_headers(config)
    agent_application_id = params.get('agent_application_id')
    endpoint = 'web/api/{0}/private/installed-applications/{1}/cves'.format(config.get('api_version'),
                                                                            agent_application_id)
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _get(headers, url, verify=verify_ssl)
    if response.get('data'):
        return response.get('data')
    elif response:
        return response
    error_handling("Failed to get application cves. ", response.text)


def get_threat_details(config, params):
    headers = _get_headers(config)
    endpoint = 'web/api/{0}/threats?ids={1}'.format(config.get('api_version'), params.get('ids'))
    url, verify_ssl = _build_url(config, method_name=endpoint)
    threat_detail = _get(headers, url, verify=verify_ssl)
    logout_user(config, headers)
    if threat_detail.get('data'):
        return threat_detail.get('data')
    elif threat_detail:
        return threat_detail
    error_handling("Failed to get threat details. ", threat_detail.text)


def list_all_threats(config, params):
    headers = _get_headers(config)
    url, verify_ssl = _build_url(config, method_name='web/api/' + config.get('api_version') + '/threats')
    additional_fields = params.get('additional_fields')
    if additional_fields:
        params.pop('additional_fields')
        params.update(additional_fields)
    payload = {k: v for k, v in params.items() if v is not None and v != ''}
    threats = _get(headers, url, verify=verify_ssl, params=payload)
    if threats:
        return threats
    error_handling("Failed to get threats. ", threats.text)


def get_threat_events(config, params):
    type_list, subtype_list = [], []
    threat_id = params.pop('threat_id')
    headers = _get_headers(config)
    url, verify_ssl = _build_url(config, method_name='web/api/' + config.get('api_version') + '/threats/' + str(
        threat_id) + '/explore/events')
    eventTypes = params.get('eventTypes')
    if eventTypes:
        for etype in eventTypes:
            type_list.append(etype.lower())
        eventTypes = ','.join(type_list)
        params.update({'eventTypes': eventTypes})
    eventSubTypes = params.get('eventSubTypes')
    if eventSubTypes:
        params.update({'eventSubTypes': eventSubTypes})
    additional_fields = params.get('additional_fields')
    if additional_fields:
        params.pop('additional_fields')
        params.update(additional_fields)
    payload = {k: v for k, v in params.items() if v is not None and v != ''}
    try:
        threats = _get(headers, url, verify=verify_ssl, params=payload)
        return threats
    except Exception as e:
        if config.get('api_version') == 'v2.0':
            return {'message': 'The API version 2.0 does not support this operation'}
        else:
            raise ConnectorError("{0}".format(str(e)))


def fetch_threats(config, params):
    headers = _get_headers(config)
    next_cursor, result, payload = '', [], {}
    additional_fields = params.get('additional_fields')
    if additional_fields:
        params.pop('additional_fields')
        params.update(additional_fields)
    payload = {k: v for k, v in params.items() if v is not None and v != ''}
    url, verify_ssl = _build_url(config, method_name='web/api/' + config.get('api_version') + '/threats')
    payload.update({'limit': 1000})
    while next_cursor != 'null':
        threats = _get(headers, url, verify=verify_ssl, params=payload)
        if threats:
            result = result + threats.get('data')
            next_cursor = threats['pagination']['nextCursor']
            if next_cursor:
                payload.update({'cursor': next_cursor})
            else:
                return {'data': result, 'pagination': {'nextCursor': None, 'totalItems': 0}}
    error_handling("Failed to get threats. ", threats.text)


def get_agent_count(config, params):
    headers = _get_headers(config)
    net_list, os_list = [], []
    networkStatuses = params.get('networkStatuses')
    if networkStatuses:
        for net in networkStatuses:
            net_list.append(net.lower())
        params.update({'networkStatuses': ','.join(net_list)})
    osTypes = params.get('osTypes')
    if osTypes:
        for ost in osTypes:
            os_list.append(OS_Type.get(ost))
        params.update({'osTypes': ','.join(os_list)})
    url, verify_ssl = _build_url(config, method_name='web/api/' + config.get('api_version') + '/agents/count')
    payload = {k: v for k, v in params.items() if v is not None and v != ''}
    agent_count = _get(headers, url, verify=verify_ssl, params=payload)
    logout_user(config, headers)
    if agent_count.get('data'):
        return agent_count.get('data')
    elif agent_count:
        return agent_count
    error_handling("Failed to get Agent Count. ", agent_count.text)


def get_agent_application(config, params):
    headers = _get_headers(config)
    endpoint = 'web/api/{0}/agents/applications?ids={1}'.format(config.get('api_version'), params.get('ids'))
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _get(headers, url, verify=verify_ssl)
    if response.get('data'):
        return response.get('data')
    elif response:
        return response
    error_handling("Failed to cancel running query. ", response.text)


def get_hash_details(config, params):
    headers = _get_headers(config)
    url, verify_ssl = _build_url(config, method_name='web/api/' + config.get('api_version') + '/hashes',
                                 params=params.get('hash_id') + '/reputation')
    logger.debug(url)
    hash_details = _get(headers, url, verify=verify_ssl)
    if hash_details.get('data'):
        return hash_details.get('data')
    elif hash_details:
        return hash_details
    error_handling("Failed to get hash details. ", hash_details.text)


def get_agent_passphrase(config, params):
    headers = _get_headers(config)
    additional_fields = params.get('additional_fields')
    if additional_fields:
        params.pop('additional_fields')
        params.update(additional_fields)
    params = get_payload(params)
    endpoint = 'web/api/{0}/agents/passphrases'.format(config.get('api_version'))
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _get(headers, url, params=params, verify=verify_ssl)
    if response:
        return response
    error_handling("Failed to get agent paraphrase. ", response.text)


def get_agents(config, params):
    headers = _get_headers(config)
    net_list = []
    networkStatuses = params.get('networkStatuses')
    if networkStatuses:
        for net in networkStatuses:
            net_list.append(net.lower())
        params.update({'networkStatuses': ','.join(net_list)})
    endpoint = 'web/api/{0}/agents'.format(config.get('api_version'))
    url, verify_ssl = _build_url(config, method_name=endpoint)
    additional_fields = params.get('additional_fields')
    if additional_fields:
        params.pop('additional_fields')
        params.update(additional_fields)
    payload = {k: v for k, v in params.items() if v is not None and v != ''}
    response = _get(headers, url, params=payload, verify=verify_ssl)
    if response:
        return response
    error_handling("Failed to receive Agent List. ", response.text)


def change_incident_status(config, params):
    headers = _get_headers(config)
    threat_id = params.get('threatID')
    endpoint = 'web/api/{0}/threats/incident'.format(config.get('api_version'))
    payload = {
        "data": {"incidentStatus": Incident_State_List[params.get('incidentStatus')]},
        "filter": {"ids": [threat_id]}
    }
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _post(headers, url, body=payload, verify=verify_ssl)
    if response.get('data'):
        return response.get('data')
    elif response:
        return response
    error_handling("Failed to change Incident state. ", response.text)


def add_note_to_a_threat(config, params):
    headers = _get_headers(config)
    threat_id = params.get('threatID')
    notes = params.get('note')
    endpoint = 'web/api/{0}/threats/notes'.format(config.get('api_version'))
    payload = {"data": {"text": notes}, "filter": {"ids": [threat_id]}}
    url, verify_ssl = _build_url(config, method_name=endpoint)
    response = _post(headers, url, body=payload, verify=verify_ssl)
    if response.get('data'):
        return response.get('data')
    elif response:
        return response
    error_handling("Failed to add note. ", response.text)


def get_output_schema_threats(config, params):
    if config.get('api_version') == 'v2.0':
        return Threats_2_0
    else:
        return Threats_2_1


def get_output_schema_threat_details(config, params):
    if config.get('api_version') == 'v2.0':
        return Threats_Details_2_0
    else:
        return Threats_Details_2_1


def get_output_schema_agents(config, params):
    if config.get('api_version') == 'v2.0':
        return Agent_2_0
    else:
        return Agent_2_1


operations = {
    'get_agents': get_agents,
    'agent_action': agent_action,
    'reconnect_agent': reconnect_agent,
    'get_agent_passphrase': get_agent_passphrase,
    'get_agent_application': get_agent_application,
    'broadcast_message_to_agent': broadcast_message_to_agent,
    'initiate_agent_scan': initiate_agent_scan,
    'abort_agent_scan': abort_agent_scan,
    'get_hash_details': get_hash_details,
    'get_threat_details': get_threat_details,
    'mitigate_threats': mitigate_threats,
    'fetch_agent_logs': fetch_agent_logs,
    'get_agent_count': get_agent_count,
    'list_all_threats': list_all_threats,
    'create_query': create_query,
    'get_query_status': get_query_status,
    'get_events': get_events,
    'get_events_by_type': get_events_by_type,
    'cancel_running_query': cancel_running_query,
    'threat_forensics': threat_forensics,
    'threat_forensic_details': threat_forensic_details,
    'export_forensics_threat': export_forensics_threat,
    'threat_seen_on_network': threat_seen_on_network,
    'free_text_filters': free_text_filters,
    'get_application_count': get_application_count,
    'get_cve': get_cve,
    'export_applications_risk': export_applications_risk,
    'get_applications': get_applications,
    'get_application_cve': get_application_cve,
    'mark_threat_as_benign': mark_threat_as_benign,
    'fetch_threats': fetch_threats,
    'get_output_schema_threats': get_output_schema_threats,
    'get_output_schema_threat_details': get_output_schema_threat_details,
    'get_output_schema_agents': get_output_schema_agents,
    'get_threat_events': get_threat_events,
    'change_incident_status': change_incident_status,
    'add_note_to_a_threat': add_note_to_a_threat
}
