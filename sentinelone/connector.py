"""
Copyright start
MIT License
Copyright (c) 2023 Fortinet Inc
Copyright end
"""

from connectors.core.connector import Connector
from connectors.core.connector import get_logger, ConnectorError

from .operations import operations
from .utils import (_check_and_convert_params,
                    _validate_credential)

logger = get_logger('sentinelOne')


class SentinelOne(Connector):
    def execute(self, config, operation, params, **kwargs):
        action = operations.get(operation)
        params = _check_and_convert_params(params)
        return action(config, params)

    def check_health(self, config):
        try:
            if not (config['host_name'] and config['apiToken']):
                raise ConnectorError('Required Config Missing')

            validate_credential_response = _validate_credential(config)
            if not validate_credential_response.ok:
                raise ConnectorError('Invalid Credential Provided')
        except Exception as Err:
            raise ConnectorError(Err)
