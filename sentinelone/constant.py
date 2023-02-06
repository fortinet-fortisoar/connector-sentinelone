""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

Threats_2_0 = {
    "data": [
        {
            "accountId": "",
            "accountName": "",
            "agentComputerName": "",
            "agentDomain": "",
            "agentId": "",
            "agentInfected": "",
            "agentIp": "",
            "agentIsActive": "",
            "agentIsDecommissioned": "",
            "agentMachineType": "",
            "agentNetworkStatus": "",
            "agentOsType": "",
            "agentVersion": "",
            "annotation": "",
            "automaticallyResolved": "",
            "browserType": "",
            "certId": "",
            "classification": "",
            "classificationSource": "",
            "classifierName": "",
            "cloudVerdict": "",
            "collectionId": "",
            "commandId": "",
            "createdAt": "",
            "createdDate": "",
            "description": "",
            "engines": [
            ],
            "external_ticket_id": "",
            "fileContentHash": "",
            "fileCreatedDate": "",
            "fileDisplayName": "",
            "fileExtensionType": "",
            "fileIsDotNet": "",
            "fileIsExecutable": "",
            "fileIsSystem": "",
            "fileMaliciousContent": "",
            "fileObjectId": "",
            "filePath": "",
            "fileSha256": "",
            "fileVerificationType": "",
            "fromCloud": "",
            "fromScan": "",
            "id": "",
            "indicators": [
            ],
            "initiatedBy": "",
            "initiatedByDescription": "",
            "initiatingUserId": "",
            "isCertValid": "",
            "isInteractiveSession": "",
            "isPartialStory": "",
            "maliciousGroupId": "",
            "maliciousProcessArguments": "",
            "markedAsBenign": "",
            "mitigationMode": "",
            "mitigationReport": {
                "kill": {
                    "status": ""
                },
                "network_quarantine": {
                    "status": ""
                },
                "quarantine": {
                    "status": ""
                },
                "remediate": {
                    "status": ""
                },
                "rollback": {
                    "status": ""
                },
                "unquarantine": {
                    "status": ""
                }
            },
            "mitigationStatus": "",
            "publisher": "",
            "rank": "",
            "resolved": "",
            "siteId": "",
            "siteName": "",
            "threatAgentVersion": "",
            "threatName": "",
            "updatedAt": "",
            "username": "",
            "whiteningOptions": [
            ]
        }
    ],
    "pagination": {
        "nextCursor": "",
        "totalItems": ""
    }
}

Threats_2_1 = {
    "data": [
        {
            "agentDetectionInfo": {
                "accountId": "",
                "accountName": "",
                "agentDetectionState": "",
                "agentDomain": "",
                "agentIpV4": "",
                "agentIpV6": "",
                "agentLastLoggedInUpn": "",
                "agentLastLoggedInUserMail": "",
                "agentLastLoggedInUserName": "",
                "agentMitigationMode": "",
                "agentOsName": "",
                "agentOsRevision": "",
                "agentRegisteredAt": "",
                "agentUuid": "",
                "agentVersion": "",
                "cloudProviders": {},
                "externalIp": "",
                "groupId": "",
                "groupName": "",
                "siteId": "",
                "siteName": ""
            },
            "agentRealtimeInfo": {
                "accountId": "",
                "accountName": "",
                "activeThreats": "",
                "agentComputerName": "",
                "agentDecommissionedAt": "",
                "agentDomain": "",
                "agentId": "",
                "agentInfected": "",
                "agentIsActive": "",
                "agentIsDecommissioned": "",
                "agentMachineType": "",
                "agentMitigationMode": "",
                "agentNetworkStatus": "",
                "agentOsName": "",
                "agentOsRevision": "",
                "agentOsType": "",
                "agentUuid": "",
                "agentVersion": "",
                "groupId": "",
                "groupName": "",
                "networkInterfaces": [
                    {
                        "id": "",
                        "inet": [
                        ],
                        "inet6": [
                        ],
                        "name": "",
                        "physical": ""
                    }
                ],
                "operationalState": "",
                "rebootRequired": "",
                "scanAbortedAt": "",
                "scanFinishedAt": "",
                "scanStartedAt": "",
                "scanStatus": "",
                "siteId": "",
                "siteName": "",
                "storageName": "",
                "storageType": "",
                "userActionsNeeded": []
            },
            "containerInfo": {
                "id": "",
                "image": "",
                "labels": "",
                "name": ""
            },
            "id": "",
            "indicators": [
                {
                    "category": "",
                    "description": "",
                    "ids": [],
                    "tactics": []
                }
            ],
            "kubernetesInfo": {
                "cluster": "",
                "controllerKind": "",
                "controllerLabels": "",
                "controllerName": "",
                "namespace": "",
                "namespaceLabels": "",
                "node": "",
                "pod": "",
                "podLabels": ""
            },
            "mitigationStatus": [
                {
                    "action": "",
                    "actionsCounters": {
                        "failed": "",
                        "notFound": "",
                        "pendingReboot": "",
                        "success": "",
                        "total": ""
                    },
                    "agentSupportsReport": "",
                    "groupNotFound": "",
                    "lastUpdate": "",
                    "latestReport": "",
                    "mitigationEndedAt": "",
                    "mitigationStartedAt": "",
                    "status": ""
                },
                {
                    "action": "",
                    "actionsCounters": "",
                    "agentSupportsReport": "",
                    "groupNotFound": "",
                    "lastUpdate": "",
                    "latestReport": "",
                    "mitigationEndedAt": "",
                    "mitigationStartedAt": "",
                    "status": ""
                }
            ],
            "threatInfo": {
                "analystVerdict": "",
                "analystVerdictDescription": "",
                "automaticallyResolved": "",
                "browserType": "",
                "certificateId": "",
                "classification": "",
                "classificationSource": "",
                "cloudFilesHashVerdict": "",
                "collectionId": "",
                "confidenceLevel": "",
                "createdAt": "",
                "detectionEngines": [
                    {
                        "key": "",
                        "title": ""
                    }
                ],
                "detectionType": "",
                "engines": [
                ],
                "externalTicketExists": "",
                "externalTicketId": "",
                "failedActions": "",
                "fileExtension": "",
                "fileExtensionType": "",
                "filePath": "",
                "fileSize": "",
                "fileVerificationType": "",
                "identifiedAt": "",
                "incidentStatus": "r",
                "incidentStatusDescription": "",
                "initiatedBy": "",
                "initiatedByDescription": "",
                "initiatingUserId": "",
                "initiatingUsername": "",
                "isFileless": "",
                "isValidCertificate": "",
                "maliciousProcessArguments": "",
                "md5": "",
                "mitigatedPreemptively": "",
                "mitigationStatus": "",
                "mitigationStatusDescription": "",
                "originatorProcess": "",
                "pendingActions": "",
                "processUser": "",
                "publisherName": "",
                "reachedEventsLimit": "",
                "rebootRequired": "",
                "sha1": "",
                "sha256": "",
                "storyline": "",
                "threatId": "",
                "threatName": "",
                "updatedAt": ""
            },
            "whiteningOptions": [
            ]
        }
    ],
    "pagination": {
        "nextCursor": "",
        "totalItems": ""
    }
}

Threats_Details_2_0 = [
    {
        "accountId": "",
        "accountName": "",
        "agentComputerName": "",
        "agentDomain": "",
        "agentId": "",
        "agentInfected": "",
        "agentIp": "",
        "agentIsActive": "",
        "agentIsDecommissioned": "",
        "agentMachineType": "",
        "agentNetworkStatus": "",
        "agentOsType": "",
        "agentVersion": "",
        "annotation": "",
        "automaticallyResolved": "",
        "browserType": "",
        "certId": "",
        "classification": "",
        "classificationSource": "",
        "classifierName": "",
        "cloudVerdict": "",
        "collectionId": "",
        "commandId": "",
        "createdAt": "",
        "createdDate": "",
        "description": "",
        "engines": [
        ],
        "external_ticket_id": "",
        "fileContentHash": "",
        "fileCreatedDate": "",
        "fileDisplayName": "",
        "fileExtensionType": "",
        "fileIsDotNet": "",
        "fileIsExecutable": "",
        "fileIsSystem": "",
        "fileMaliciousContent": "",
        "fileObjectId": "",
        "filePath": "",
        "fileSha256": "",
        "fileVerificationType": "",
        "fromCloud": "",
        "fromScan": "",
        "id": "",
        "indicators": [
        ],
        "initiatedBy": "",
        "initiatedByDescription": "",
        "initiatingUserId": "",
        "isCertValid": "",
        "isInteractiveSession": "",
        "isPartialStory": "",
        "maliciousGroupId": "",
        "maliciousProcessArguments": "",
        "markedAsBenign": "",
        "mitigationMode": "",
        "mitigationReport": {
            "kill": {
                "status": ""
            },
            "network_quarantine": {
                "status": ""
            },
            "quarantine": {
                "status": ""
            },
            "remediate": {
                "status": ""
            },
            "rollback": {
                "status": ""
            },
            "unquarantine": {
                "status": ""
            }
        },
        "mitigationStatus": "",
        "publisher": "",
        "rank": "",
        "resolved": "",
        "siteId": "",
        "siteName": "",
        "threatAgentVersion": "",
        "threatName": "",
        "updatedAt": "",
        "username": "",
        "whiteningOptions": [
        ]
    }
]

Threats_Details_2_1 = [
    {
        "agentDetectionInfo": {
            "accountId": "",
            "accountName": "",
            "agentDetectionState": "",
            "agentDomain": "",
            "agentIpV4": "",
            "agentIpV6": "",
            "agentLastLoggedInUpn": "",
            "agentLastLoggedInUserMail": "",
            "agentLastLoggedInUserName": "",
            "agentMitigationMode": "",
            "agentOsName": "",
            "agentOsRevision": "",
            "agentRegisteredAt": "",
            "agentUuid": "",
            "agentVersion": "",
            "cloudProviders": {},
            "externalIp": "",
            "groupId": "",
            "groupName": "",
            "siteId": "",
            "siteName": ""
        },
        "agentRealtimeInfo": {
            "accountId": "",
            "accountName": "",
            "activeThreats": "",
            "agentComputerName": "",
            "agentDecommissionedAt": "",
            "agentDomain": "",
            "agentId": "",
            "agentInfected": "",
            "agentIsActive": "",
            "agentIsDecommissioned": "",
            "agentMachineType": "",
            "agentMitigationMode": "",
            "agentNetworkStatus": "",
            "agentOsName": "",
            "agentOsRevision": "",
            "agentOsType": "",
            "agentUuid": "",
            "agentVersion": "",
            "groupId": "",
            "groupName": "",
            "networkInterfaces": [
                {
                    "id": "",
                    "inet": [
                    ],
                    "inet6": [
                    ],
                    "name": "",
                    "physical": ""
                }
            ],
            "operationalState": "",
            "rebootRequired": "",
            "scanAbortedAt": "",
            "scanFinishedAt": "",
            "scanStartedAt": "",
            "scanStatus": "",
            "siteId": "",
            "siteName": "",
            "storageName": "",
            "storageType": "",
            "userActionsNeeded": []
        },
        "containerInfo": {
            "id": "",
            "image": "",
            "labels": "",
            "name": ""
        },
        "id": "",
        "indicators": [
            {
                "category": "",
                "description": "",
                "ids": [],
                "tactics": []
            }
        ],
        "kubernetesInfo": {
            "cluster": "",
            "controllerKind": "",
            "controllerLabels": "",
            "controllerName": "",
            "namespace": "",
            "namespaceLabels": "",
            "node": "",
            "pod": "",
            "podLabels": ""
        },
        "mitigationStatus": [
            {
                "action": "",
                "actionsCounters": {
                    "failed": "",
                    "notFound": "",
                    "pendingReboot": "",
                    "success": "",
                    "total": ""
                },
                "agentSupportsReport": "",
                "groupNotFound": "",
                "lastUpdate": "",
                "latestReport": "",
                "mitigationEndedAt": "",
                "mitigationStartedAt": "",
                "status": ""
            },
            {
                "action": "",
                "actionsCounters": "",
                "agentSupportsReport": "",
                "groupNotFound": "",
                "lastUpdate": "",
                "latestReport": "",
                "mitigationEndedAt": "",
                "mitigationStartedAt": "",
                "status": ""
            }
        ],
        "threatInfo": {
            "analystVerdict": "",
            "analystVerdictDescription": "",
            "automaticallyResolved": "",
            "browserType": "",
            "certificateId": "",
            "classification": "",
            "classificationSource": "",
            "cloudFilesHashVerdict": "",
            "collectionId": "",
            "confidenceLevel": "",
            "createdAt": "",
            "detectionEngines": [
                {
                    "key": "",
                    "title": ""
                }
            ],
            "detectionType": "",
            "engines": [
            ],
            "externalTicketExists": "",
            "externalTicketId": "",
            "failedActions": "",
            "fileExtension": "",
            "fileExtensionType": "",
            "filePath": "",
            "fileSize": "",
            "fileVerificationType": "",
            "identifiedAt": "",
            "incidentStatus": "r",
            "incidentStatusDescription": "",
            "initiatedBy": "",
            "initiatedByDescription": "",
            "initiatingUserId": "",
            "initiatingUsername": "",
            "isFileless": "",
            "isValidCertificate": "",
            "maliciousProcessArguments": "",
            "md5": "",
            "mitigatedPreemptively": "",
            "mitigationStatus": "",
            "mitigationStatusDescription": "",
            "originatorProcess": "",
            "pendingActions": "",
            "processUser": "",
            "publisherName": "",
            "reachedEventsLimit": "",
            "rebootRequired": "",
            "sha1": "",
            "sha256": "",
            "storyline": "",
            "threatId": "",
            "threatName": "",
            "updatedAt": ""
        },
        "whiteningOptions": [
        ]
    }
]

Agent_2_0 = {
    "data": [
        {
            "accountId": "",
            "accountName": "",
            "activeDirectory": {
                "computerDistinguishedName": "",
                "computerMemberOf": [],
                "lastUserDistinguishedName": "",
                "lastUserMemberOf": []
            },
            "activeThreats": "",
            "agentVersion": "",
            "allowRemoteShell": "",
            "appsVulnerabilityStatus": "",
            "computerName": "",
            "consoleMigrationStatus": "",
            "coreCount": "",
            "cpuCount": "",
            "cpuId": "",
            "createdAt": "",
            "domain": "",
            "encryptedApplications": "",
            "externalId": "",
            "externalIp": "",
            "groupId": "",
            "groupIp": "",
            "groupName": "",
            "id": "",
            "inRemoteShellSession": "",
            "infected": "",
            "installerType": "",
            "isActive": "",
            "isDecommissioned": "",
            "isPendingUninstall": "",
            "isUninstalled": "",
            "isUpToDate": "",
            "lastActiveDate": "",
            "lastIpToMgmt": "",
            "lastLoggedInUserName": "",
            "licenseKey": "",
            "locationType": "",
            "locations": [
                {
                    "id": "",
                    "name": "",
                    "scope": ""
                }
            ],
            "machineType": "",
            "mitigationMode": "",
            "mitigationModeSuspicious": "",
            "modelName": "",
            "networkInterfaces": [
                {
                    "id": "",
                    "inet": [
                    ],
                    "inet6": [
                    ],
                    "name": "",
                    "physical": ""
                }
            ],
            "networkStatus": "",
            "osArch": "",
            "osName": "",
            "osRevision": "",
            "osStartTime": "",
            "osType": "",
            "osUsername": "",
            "rangerStatus": "",
            "rangerVersion": "",
            "registeredAt": "",
            "scanAbortedAt": "",
            "scanFinishedAt": "",
            "scanStartedAt": "",
            "scanStatus": "",
            "siteId": "",
            "siteName": "",
            "threatRebootRequired": "",
            "totalMemory": "",
            "updatedAt": "",
            "userActionsNeeded": [],
            "uuid": ""
        }
    ],
    "pagination": {
        "nextCursor": "",
        "totalItems": ""
    }
}

Agent_2_1 = {
    "data": [
        {
            "accountId": "",
            "accountName": "",
            "activeDirectory": {
                "computerDistinguishedName": "",
                "computerMemberOf": [],
                "lastUserDistinguishedName": "",
                "lastUserMemberOf": []
            },
            "activeThreats": "",
            "agentVersion": "",
            "allowRemoteShell": "",
            "appsVulnerabilityStatus": "",
            "cloudProviders": {},
            "computerName": "",
            "consoleMigrationStatus": "",
            "coreCount": "",
            "cpuCount": "",
            "cpuId": "",
            "createdAt": "",
            "detectionState": "",
            "domain": "",
            "encryptedApplications": "",
            "externalId": "",
            "externalIp": "",
            "firewallEnabled": "",
            "firstFullModeTime": "",
            "groupId": "",
            "groupIp": "",
            "groupName": "",
            "id": "",
            "inRemoteShellSession": "",
            "infected": "",
            "installerType": "",
            "isActive": "",
            "isDecommissioned": "",
            "isPendingUninstall": "",
            "isUninstalled": "",
            "isUpToDate": "",
            "lastActiveDate": "",
            "lastIpToMgmt": "",
            "lastLoggedInUserName": "",
            "licenseKey": "",
            "locationEnabled": "",
            "locationType": "",
            "locations": [
                {
                    "id": "",
                    "name": "",
                    "scope": ""
                }
            ],
            "machineType": "",
            "mitigationMode": "",
            "mitigationModeSuspicious": "",
            "modelName": "",
            "networkInterfaces": [
                {
                    "gatewayIp": "",
                    "gatewayMacAddress": "",
                    "id": "",
                    "inet": [
                    ],
                    "inet6": [
                    ],
                    "name": "",
                    "physical": ""
                }
            ],
            "networkQuarantineEnabled": "",
            "networkStatus": "",
            "operationalState": "",
            "operationalStateExpiration": "",
            "osArch": "",
            "osName": "",
            "osRevision": "",
            "osStartTime": "",
            "osType": "",
            "osUsername": "",
            "rangerStatus": "",
            "rangerVersion": "",
            "registeredAt": "",
            "remoteProfilingState": "",
            "remoteProfilingStateExpiration": "",
            "scanAbortedAt": "",
            "scanFinishedAt": "",
            "scanStartedAt": "",
            "scanStatus": "",
            "serialNumber": "",
            "siteId": "",
            "siteName": "",
            "storageName": "",
            "storageType": "",
            "tags": {
                "sentinelone": [
                    {
                        "assignedAt": "",
                        "assignedBy": "",
                        "assignedById": "",
                        "id": "",
                        "key": "",
                        "value": ""
                    }
                ]
            },
            "threatRebootRequired": "",
            "totalMemory": "",
            "updatedAt": "",
            "userActionsNeeded": [],
            "uuid": ""
        }
    ],
    "pagination": {
        "nextCursor": "",
        "totalItems": ""
    }
}

OS_Type = {
    'Linux': 'linux',
    'MacOS': 'macos',
    'Windows': 'windows',
    'Windows Legacy': 'windows_legacy'
}

APP_Type_List = {
    "App": "app",
    "Kb": "kb",
    "Patch": "patch",
    "ChromeExtension": "chromeExtension",
    "EdgeExtension": "edgeExtension",
    "FirefoxExtension": "firefoxExtension",
    "SafariExtension": "safariExtension"
}

Sort_Type = {
    'Ascending': 'asc',
    'Descending': 'desc'
}
