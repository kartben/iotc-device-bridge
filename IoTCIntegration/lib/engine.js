/*!
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

const crypto = require('crypto');

const Device = require('azure-iot-device');
const DeviceTransport = require('azure-iot-device-mqtt');
var ProvisioningTransport = require('azure-iot-provisioning-device-mqtt').Mqtt;
var SymmetricKeySecurityClient = require('azure-iot-security-symmetric-key').SymmetricKeySecurityClient;
var ProvisioningDeviceClient = require('azure-iot-provisioning-device').ProvisioningDeviceClient;

const StatusError = require('../error').StatusError;

const registrationHost = 'global.azure-devices-provisioning.net';

const deviceCache = {};

/**
 * Forwards external telemetry messages for IoT Central devices.
 * @param {{ idScope: string, primaryKeyUrl: string, log: Function, getSecret: (context: Object, secretUrl: string) => string }} context 
 * @param {{ deviceId: string }} device 
 * @param {{ [field: string]: number }} measurements 
 * @param {{ [field: string]: Object }} properties 
 * @param { String } timestamp 
 */
module.exports = async function (context, device, measurements, properties, timestamp) {
    if (device) {
        if (!device.deviceId || !/^[a-z0-9\-]+$/.test(device.deviceId)) {
            throw new StatusError('Invalid format: deviceId must be alphanumeric, lowercase, and may contain hyphens.', 400);
        }
    } else {
        throw new StatusError('Invalid format: a device specification must be provided.', 400);
    }

    if (!validateMeasurements(measurements)) {
        throw new StatusError('Invalid format: invalid measurement list.', 400);
    }

    // TODO validate properties

    if (timestamp && isNaN(Date.parse(timestamp))) {
        throw new StatusError('Invalid format: if present, timestamp must be in ISO format (e.g., YYYY-MM-DDTHH:mm:ss.sssZ)', 400);
    }

    try {
        const client = Device.Client.fromConnectionString(await getDeviceConnectionString(context, device), DeviceTransport.Mqtt);
        context.log('DEVICE CACHE: ', deviceCache);
    
        const message = new Device.Message(JSON.stringify(measurements));

        if (timestamp) {
            message.properties.add('iothub-creation-time-utc', timestamp);
        }

        await client.open();
        context.log('[MQTT] Sending telemetry for device ', device.deviceId);
        await client.sendEvent(message);
        if (properties) {
            context.log('[MQTT] Get twin', device.deviceId);
            var twin = await client.getTwin();
            context.log('[MQTT] Obtained twin for device ', device.deviceId);
            await twin.properties.reported.update(properties);
            context.log('[MQTT] Updated twin for device ', device.deviceId);
        }
        await client.close();
        context.log('[MQTT] Client closed for ', device.deviceId);
    } catch (e) {
        // If the device was deleted, we remove its cached connection string
        if (e.name === 'DeviceNotFoundError' && deviceCache[device.deviceId]) {
            delete deviceCache[device.deviceId].connectionString;
        }

        throw new Error(`Unable to send telemetry for device ${device.deviceId}: ${e.message}`);
    }
};

/**
 * @returns true if measurements object is valid, i.e., a map of field names to numbers or strings.
 */
function validateMeasurements(measurements) {
    if (!measurements || typeof measurements !== 'object') {
        return false;
    }

    for (const field in measurements) {
        if (typeof measurements[field] !== 'number' && typeof measurements[field] !== 'string') {
            return false;
        }
    }

    return true;
}

async function getDeviceConnectionString(context, device) {
    const deviceId = device.deviceId;

    if (deviceCache[deviceId] && deviceCache[deviceId].connectionString) {
        return deviceCache[deviceId].connectionString;
    }

    var symmetricKey = await getDeviceKey(context, deviceId);
    var provisioningSecurityClient = new SymmetricKeySecurityClient(deviceId, symmetricKey);
    var provisioningClient = ProvisioningDeviceClient.create(registrationHost, context.idScope, new ProvisioningTransport(), provisioningSecurityClient);

    var registrationResult = await provisioningClient.register();

    const connStr = 'HostName=' + registrationResult.assignedHub + ';DeviceId=' + registrationResult.deviceId + ';SharedAccessKey=' + symmetricKey;
    deviceCache[deviceId].connectionString = connStr;
    return connStr;
}

/**
 * Computes a derived device key using the primary key.
 */
async function getDeviceKey(context, deviceId) {
    if (deviceCache[deviceId] && deviceCache[deviceId].deviceKey) {
        return deviceCache[deviceId].deviceKey;
    }

    const key = crypto.createHmac('SHA256', Buffer.from(await context.getSecret(context, context.primaryKeyUrl), 'base64'))
        .update(deviceId)
        .digest()
        .toString('base64');

    deviceCache[deviceId] = {
        ...deviceCache[deviceId],
        deviceId: key
    } 

    return key;
}