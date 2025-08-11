# FIDO2 Passkey Metrics Configuration

This document describes the new passkey metrics configuration feature in Jans FIDO2 server.

## Overview

The passkey metrics configuration allows administrators to control the collection and storage of passkey-related metrics for better visibility into passkey adoption and usage patterns.

## Configuration Properties

### Core Metrics Settings

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `passkeyMetricsEnabled` | Boolean | `true` | Enable/disable passkey metrics collection |
| `passkeyMetricsRetentionDays` | Integer | `90` | Number of days to retain metrics data |
| `passkeyMetricsAsyncStorage` | Boolean | `true` | Use async storage for better performance |
| `passkeyMetricsBatchSize` | Integer | `100` | Batch size for metrics storage |

### Granular Control

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `registrationMetricsEnabled` | Boolean | `true` | Enable registration metrics collection |
| `authenticationMetricsEnabled` | Boolean | `true` | Enable authentication metrics collection |
| `deviceInfoCollection` | Boolean | `true` | Collect device information with metrics |
| `errorCategorization` | Boolean | `true` | Categorize errors for better analysis |

## Config API Endpoints

### Get Metrics Configuration

```bash
GET /jans-config-api/fido2/fido2-config/metrics
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "passkeyMetricsEnabled": true,
  "passkeyMetricsRetentionDays": 90,
  "passkeyMetricsAsyncStorage": true,
  "passkeyMetricsBatchSize": 100,
  "registrationMetricsEnabled": true,
  "authenticationMetricsEnabled": true,
  "deviceInfoCollection": true,
  "errorCategorization": true
}
```

### Update Metrics Configuration

```bash
PUT /jans-config-api/fido2/fido2-config/metrics
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "passkeyMetricsEnabled": true,
  "passkeyMetricsRetentionDays": 60,
  "passkeyMetricsAsyncStorage": false,
  "passkeyMetricsBatchSize": 200,
  "registrationMetricsEnabled": true,
  "authenticationMetricsEnabled": false,
  "deviceInfoCollection": true,
  "errorCategorization": false
}
```

## Terraform Configuration

You can manage the passkey metrics configuration using Terraform:

```hcl
resource "jans_fido2_configuration" "fido2" {
  passkey_metrics_enabled        = true
  passkey_metrics_retention_days = 90
  passkey_metrics_async_storage  = true
  passkey_metrics_batch_size     = 100
  registration_metrics_enabled    = true
  authentication_metrics_enabled  = true
  device_info_collection         = true
  error_categorization           = true
}
```

## TUI Configuration

The passkey metrics configuration is available through the Jans CLI TUI:

```bash
jans-cli-tui
```

Navigate to: **Configuration** → **FIDO2** → **Metrics Configuration**

## Metrics Collected

When enabled, the following metrics are collected:

### Registration Metrics
- Registration attempts
- Registration successes
- Registration failures
- Registration completion time
- Device information

### Authentication Metrics
- Authentication attempts
- Authentication successes
- Authentication failures
- Authentication completion time
- Performance comparison with passwords

### Nudge Metrics
- Nudge impressions
- Nudge acceptance rate
- Nudge decline rate

### Fallback Metrics
- Fallback frequency
- Fallback reasons
- Fallback resolution time

## Performance Considerations

- **Async Storage**: Enabled by default for better performance
- **Batch Processing**: Configurable batch size for optimal throughput
- **Retention Policy**: Configurable retention period to manage storage
- **Granular Control**: Enable/disable specific metric types as needed

## Security

- Metrics collection respects user privacy
- No personally identifiable information is stored
- Device information is anonymized
- Error details are sanitized

## Troubleshooting

### Metrics Not Being Collected

1. Check if `passkeyMetricsEnabled` is set to `true`
2. Verify the specific metric type is enabled (e.g., `registrationMetricsEnabled`)
3. Check server logs for any metrics-related errors
4. Ensure the MetricService is properly initialized

### Performance Issues

1. Reduce `passkeyMetricsBatchSize` if experiencing memory issues
2. Disable `passkeyMetricsAsyncStorage` if async processing causes problems
3. Reduce `passkeyMetricsRetentionDays` to manage storage usage
4. Disable specific metric types that are not needed

### Configuration Issues

1. Verify the Config API endpoints are accessible
2. Check authentication and authorization
3. Ensure the configuration is properly saved
4. Restart the FIDO2 service after configuration changes

## Migration

For existing installations:

1. The new metrics configuration is disabled by default
2. Enable metrics collection gradually to monitor performance impact
3. Start with basic metrics and enable advanced features as needed
4. Monitor storage usage and adjust retention policies accordingly 