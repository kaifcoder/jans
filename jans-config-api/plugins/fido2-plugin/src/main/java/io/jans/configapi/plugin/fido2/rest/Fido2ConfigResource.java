/*
 * Janssen Project software is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.configapi.plugin.fido2.rest;

import io.jans.configapi.plugin.fido2.service.Fido2Service;
import io.jans.configapi.plugin.fido2.util.Fido2Util;
import io.jans.configapi.plugin.fido2.util.Constants;
import io.jans.configapi.core.rest.BaseResource;
import io.jans.configapi.core.rest.ProtectedApi;
import io.jans.fido2.model.conf.AppConfiguration;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.inject.Inject;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.slf4j.Logger;

/**
 * @author Yuriy Movchan
 * @version May 08, 2020
 */
@Tag(name = "Fido2 - Configuration", description = "Fido2 Configuration endpoint")
@Path(Constants.FIDO2_CONFIG)
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class Fido2ConfigResource extends BaseResource {

    private static final String FIDO2_CONFIGURATION = "fido2Configuration";

    @Inject
    Logger logger;

    @Inject
    Fido2Service fido2Service;

    @Inject
    Fido2Util fido2Util;

    @Operation(summary = "Gets Jans Authorization Server Fido2 configuration properties", description = "Gets Jans Authorization Server Fido2 configuration properties", operationId = "get-properties-fido2", tags = {
            "Fido2 - Configuration" }, security = @SecurityRequirement(name = "oauth2", scopes = {
                    Constants.FIDO2_CONFIG_READ_ACCESS }))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Ok", content = @Content(mediaType = MediaType.APPLICATION_JSON, schema = @Schema(implementation = AppConfiguration.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "500", description = "InternalServerError") })
    @GET
    @ProtectedApi(scopes = { Constants.FIDO2_CONFIG_READ_ACCESS })
    public Response getFido2Configuration() {
        AppConfiguration appConfiguration = this.fido2Service.find();
        logger.debug("FIDO2 configuration:{}", appConfiguration);
        return Response.ok(appConfiguration).build();
    }

    @Operation(summary = "Updates Fido2 configuration properties", description = "Updates Fido2 configuration properties", operationId = "put-properties-fido2", tags = {
            "Fido2 - Configuration" }, security = @SecurityRequirement(name = "oauth2", scopes = {
                    Constants.FIDO2_CONFIG_WRITE_ACCESS }))
    @RequestBody(description = "Fido2Config", content = @Content(mediaType = MediaType.APPLICATION_JSON, schema = @Schema(implementation = AppConfiguration.class)))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Fido2Config", content = @Content(mediaType = MediaType.APPLICATION_JSON, schema = @Schema(implementation = AppConfiguration.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "500", description = "InternalServerError") })
    @PUT
    @ProtectedApi(scopes = { Constants.FIDO2_CONFIG_WRITE_ACCESS })
    public Response updateFido2Configuration(@NotNull AppConfiguration appConfiguration) {
        logger.debug("FIDO2 configuration to be updated:{} ", appConfiguration);
        checkResourceNotNull(appConfiguration, FIDO2_CONFIGURATION);
        this.fido2Service.merge(appConfiguration);
        return getFido2Configuration();
    }

    @Operation(summary = "Gets Fido2 passkey metrics configuration", description = "Gets Fido2 passkey metrics configuration properties", operationId = "get-fido2-metrics-config", tags = {
            "Fido2 - Configuration" }, security = @SecurityRequirement(name = "oauth2", scopes = {
                    Constants.FIDO2_CONFIG_READ_ACCESS }))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Fido2 Metrics Config", content = @Content(mediaType = MediaType.APPLICATION_JSON, schema = @Schema(implementation = PasskeyMetricsConfig.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "500", description = "InternalServerError") })
    @GET
    @Path("/metrics")
    @ProtectedApi(scopes = { Constants.FIDO2_CONFIG_READ_ACCESS })
    public Response getFido2MetricsConfiguration() {
        AppConfiguration appConfiguration = this.fido2Service.find();
        logger.debug("FIDO2 metrics configuration:{}", appConfiguration);
        
        PasskeyMetricsConfig metricsConfig = new PasskeyMetricsConfig();
        metricsConfig.setPasskeyMetricsEnabled(appConfiguration.getPasskeyMetricsEnabled());
        metricsConfig.setPasskeyMetricsRetentionDays(appConfiguration.getPasskeyMetricsRetentionDays());
        metricsConfig.setPasskeyMetricsAsyncStorage(appConfiguration.getPasskeyMetricsAsyncStorage());
        metricsConfig.setPasskeyMetricsBatchSize(appConfiguration.getPasskeyMetricsBatchSize());
        metricsConfig.setRegistrationMetricsEnabled(appConfiguration.getRegistrationMetricsEnabled());
        metricsConfig.setAuthenticationMetricsEnabled(appConfiguration.getAuthenticationMetricsEnabled());
        metricsConfig.setDeviceInfoCollection(appConfiguration.getDeviceInfoCollection());
        metricsConfig.setErrorCategorization(appConfiguration.getErrorCategorization());
        
        return Response.ok(metricsConfig).build();
    }

    @Operation(summary = "Updates Fido2 passkey metrics configuration", description = "Updates Fido2 passkey metrics configuration properties", operationId = "put-fido2-metrics-config", tags = {
            "Fido2 - Configuration" }, security = @SecurityRequirement(name = "oauth2", scopes = {
                    Constants.FIDO2_CONFIG_WRITE_ACCESS }))
    @RequestBody(description = "Fido2 Metrics Config", content = @Content(mediaType = MediaType.APPLICATION_JSON, schema = @Schema(implementation = PasskeyMetricsConfig.class)))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Fido2 Metrics Config", content = @Content(mediaType = MediaType.APPLICATION_JSON, schema = @Schema(implementation = PasskeyMetricsConfig.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "500", description = "InternalServerError") })
    @PUT
    @Path("/metrics")
    @ProtectedApi(scopes = { Constants.FIDO2_CONFIG_WRITE_ACCESS })
    public Response updateFido2MetricsConfiguration(@NotNull PasskeyMetricsConfig metricsConfig) {
        logger.debug("FIDO2 metrics configuration to be updated:{} ", metricsConfig);
        checkResourceNotNull(metricsConfig, "fido2MetricsConfiguration");
        
        AppConfiguration appConfiguration = this.fido2Service.find();
        
        // Update only the metrics-related properties
        appConfiguration.setPasskeyMetricsEnabled(metricsConfig.getPasskeyMetricsEnabled());
        appConfiguration.setPasskeyMetricsRetentionDays(metricsConfig.getPasskeyMetricsRetentionDays());
        appConfiguration.setPasskeyMetricsAsyncStorage(metricsConfig.getPasskeyMetricsAsyncStorage());
        appConfiguration.setPasskeyMetricsBatchSize(metricsConfig.getPasskeyMetricsBatchSize());
        appConfiguration.setRegistrationMetricsEnabled(metricsConfig.getRegistrationMetricsEnabled());
        appConfiguration.setAuthenticationMetricsEnabled(metricsConfig.getAuthenticationMetricsEnabled());
        appConfiguration.setDeviceInfoCollection(metricsConfig.getDeviceInfoCollection());
        appConfiguration.setErrorCategorization(metricsConfig.getErrorCategorization());
        
        this.fido2Service.merge(appConfiguration);
        
        // Return the updated metrics config
        return getFido2MetricsConfiguration();
    }

    /**
     * Passkey Metrics Configuration DTO
     */
    public static class PasskeyMetricsConfig {
        private Boolean passkeyMetricsEnabled;
        private Integer passkeyMetricsRetentionDays;
        private Boolean passkeyMetricsAsyncStorage;
        private Integer passkeyMetricsBatchSize;
        private Boolean registrationMetricsEnabled;
        private Boolean authenticationMetricsEnabled;
        private Boolean deviceInfoCollection;
        private Boolean errorCategorization;

        // Getters and Setters
        public Boolean getPasskeyMetricsEnabled() {
            return passkeyMetricsEnabled;
        }

        public void setPasskeyMetricsEnabled(Boolean passkeyMetricsEnabled) {
            this.passkeyMetricsEnabled = passkeyMetricsEnabled;
        }

        public Integer getPasskeyMetricsRetentionDays() {
            return passkeyMetricsRetentionDays;
        }

        public void setPasskeyMetricsRetentionDays(Integer passkeyMetricsRetentionDays) {
            this.passkeyMetricsRetentionDays = passkeyMetricsRetentionDays;
        }

        public Boolean getPasskeyMetricsAsyncStorage() {
            return passkeyMetricsAsyncStorage;
        }

        public void setPasskeyMetricsAsyncStorage(Boolean passkeyMetricsAsyncStorage) {
            this.passkeyMetricsAsyncStorage = passkeyMetricsAsyncStorage;
        }

        public Integer getPasskeyMetricsBatchSize() {
            return passkeyMetricsBatchSize;
        }

        public void setPasskeyMetricsBatchSize(Integer passkeyMetricsBatchSize) {
            this.passkeyMetricsBatchSize = passkeyMetricsBatchSize;
        }

        public Boolean getRegistrationMetricsEnabled() {
            return registrationMetricsEnabled;
        }

        public void setRegistrationMetricsEnabled(Boolean registrationMetricsEnabled) {
            this.registrationMetricsEnabled = registrationMetricsEnabled;
        }

        public Boolean getAuthenticationMetricsEnabled() {
            return authenticationMetricsEnabled;
        }

        public void setAuthenticationMetricsEnabled(Boolean authenticationMetricsEnabled) {
            this.authenticationMetricsEnabled = authenticationMetricsEnabled;
        }

        public Boolean getDeviceInfoCollection() {
            return deviceInfoCollection;
        }

        public void setDeviceInfoCollection(Boolean deviceInfoCollection) {
            this.deviceInfoCollection = deviceInfoCollection;
        }

        public Boolean getErrorCategorization() {
            return errorCategorization;
        }

        public void setErrorCategorization(Boolean errorCategorization) {
            this.errorCategorization = errorCategorization;
        }
    }
}