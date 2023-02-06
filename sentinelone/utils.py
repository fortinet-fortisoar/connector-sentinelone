""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import json
from requests import get, post, exceptions
from sys import _getframe

from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('sentinelOne')


def _create_login_request_body(config, params=None):
    return {
        "data":
            {
                "apiToken": config.get('apiToken')
            }
    }


def _get(headers, url, params=None, verify=True, timeout=12):
    try:
        res = get(url, params=params, headers=headers, timeout=timeout, verify=verify)
        if res.ok or res.status_code == 204:
            if 'json' in str(res.headers):
                return res.json()
            else:
                return res
        elif res.status_code == 404:
            return res.json()
        else:
            logger.error("{0}".format(res.text))
            raise ConnectorError("{0}".format(res.text))
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def _post(headers, url, body={}, verify=True, timeout=12):
    try:
        res = post(url, data=json.dumps(body), headers=headers, timeout=timeout, verify=verify)
        if res.ok or res.status_code == 204:
            if 'json' in str(res.headers):
                return res.json()
            else:
                return res
        elif res.status_code == 404:
            return res.json()
        else:
            logger.error("{0}".format(res.text))
            raise ConnectorError("{0}".format(res.text))
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def logout_user(config, headers):
    url, verify_ssl = _build_url(config, method_name='web/api/' + config.get('api_version') + '/users/logout')
    logger.info(url)
    logout = _post(headers, url, body={})
    return logout


def _check_and_convert_params(params):
    convert_params = dict()
    if params:
        for k, v in params.items():
            if type(v) == bytes:
                convert_params[k] = str(v, 'utf-8')
            else:
                convert_params[k] = v
    return convert_params


def _build_url(config, method_name, params=None, query_params=None):
    """ Concatenate URLs """
    host_name = config.get('host_name')
    if not host_name.startswith('https://'):
        base_url = 'https://{0}/'.format(config.get('host_name'))
    else:
        base_url = host_name + '/'
    if not params and not query_params:
        url = '{base_url}{method_name}'.format(
            base_url=base_url, method_name=method_name)
    elif params and not query_params:
        url = '{base_url}{method_name}/{params}'.format(
            base_url=base_url, method_name=method_name, params=params)
    elif params and query_params:
        url = '{base_url}{method_name}/{params}?{query_params}'.format(
            base_url=base_url, method_name=method_name, params=params, query_params=query_params)
    elif query_params and not params:
        url = '{base_url}{method_name}?{query_params}'.format(
            base_url=base_url, method_name=method_name, query_params=query_params)
    else:
        url = base_url
    verify_ssl = config.get('verify_ssl', True)
    return url, verify_ssl


def _generate_headers(token=None):
    headers = dict()
    headers['content-type'] = 'application/json'
    if token:
        headers['Authorization'] = 'Token ' + token
    return headers


def _validate_credential(config):
    url, verify_ssl = _build_url(config,
                                 method_name='web/api/' + config.get('api_version') + '/users/login/by-api-token')

    request_body = _create_login_request_body(config)
    headers = {'content-type': 'application/json'}
    try:
        res = post(url, data=json.dumps(request_body), headers=headers, timeout=12, verify=verify_ssl)
        return res
    except exceptions.RequestException as e:
        raise ConnectorError("Invalid URI or credentials")


def _get_headers(config):
    validate_credential_response = _validate_credential(config)
    token = validate_credential_response.json().get('data').get('token')
    headers = _generate_headers(token)
    return headers


def build_query(query_params, params, param, counter):
    if params.get(param) or params.get(param) == False:
        if params[param] == True:
            par = "true"
        elif params[param] is 0:
            par = 0
        elif params[param] is False:
            par = "false"
        else:
            if param in ['network_status__in', 'os_type__in', 'action']:
                par = params[param].lower()
            else:
                par = params[param]
        if counter:
            query_params += '&' + param + '=' + str(par)
        else:
            query_params = param + '=' + str(par)
    return query_params


def _build_query_params(params, allowed_blank_param=False):
    counter = 0
    query_params = ''
    all_filter = params.keys()
    for fil_ele in all_filter:
        query_params = build_query(query_params, params, fil_ele, counter)
        counter += 1
    if query_params == '' and allowed_blank_param is False:
        raise ConnectorError('At least one filter params need to be passed for the operation')
    return query_params


def error_handling(error_msg, api_response_text):
    logger.error(error_msg + "Server responded with {error_message} message".format(
        error_message=api_response_text))
    raise ConnectorError(error_msg + "Server responded with {error_message} message".format(
        error_message=api_response_text))
