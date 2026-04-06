"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

from connectors.core.connector import Connector
from connectors.core.connector import get_logger, ConnectorError
from .constants import LOGGER_NAME
from .operations import functions
logger = get_logger(LOGGER_NAME)


class InvestigationReportConnector(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            action = functions.get(operation)
            logger.debug('Action name {}'.format(action))
            return action(config, params)
        except Exception as e:
            raise ConnectorError('{}'.format(e))

    def check_health(self, config):
        return True
