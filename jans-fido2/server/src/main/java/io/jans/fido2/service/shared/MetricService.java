/*
 * Janssen Project software is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.fido2.service.shared;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.inject.Named;

import io.jans.fido2.model.conf.AppConfiguration;
import io.jans.model.ApplicationType;
import io.jans.as.common.service.common.ApplicationFactory;
import io.jans.as.model.config.StaticConfiguration;
import io.jans.orm.PersistenceEntryManager;
import io.jans.service.metric.inject.ReportMetric;
import io.jans.service.net.NetworkService;
import io.jans.model.metric.MetricType;
import io.jans.model.metric.ldap.MetricEntry;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Store and retrieve metric
 *
 * @author Yuriy Movchan Date: 05/13/2020
 */
@ApplicationScoped
@Named(MetricService.METRIC_SERVICE_COMPONENT_NAME)
public class MetricService extends io.jans.service.metric.MetricService {
	
	public static final String METRIC_SERVICE_COMPONENT_NAME = "metricService";

	private static final long serialVersionUID = 7875838160379126796L;

	@Inject
    private Instance<MetricService> instance;

	@Inject
	private AppConfiguration appConfiguration;

	@Inject
    private StaticConfiguration staticConfiguration;

	@Inject
    private NetworkService networkService;

    @Inject
    @Named(ApplicationFactory.PERSISTENCE_METRIC_ENTRY_MANAGER_NAME)
    @ReportMetric
    private PersistenceEntryManager persistenceEntryManager;

    // Async executor for metrics recording
    private final ExecutorService metricsExecutor = Executors.newSingleThreadExecutor();

    public void initTimer() {
    	initTimer(this.appConfiguration.getMetricReporterInterval(), this.appConfiguration.getMetricReporterKeepDataDays());
    }

	@Override
	public String baseDn() {
		return staticConfiguration.getBaseDn().getMetric();
	}

	public io.jans.service.metric.MetricService getMetricServiceInstance() {
		return instance.get();
	}

    @Override
    public boolean isMetricReporterEnabled() {
        return this.appConfiguration.getMetricReporterEnabled();
    }

    @Override
    public ApplicationType getApplicationType() {
        return ApplicationType.FIDO2;
    }

    @Override
    public PersistenceEntryManager getEntryManager() {
        return persistenceEntryManager;
    }

	@Override
	public String getNodeIndetifier() {
		return networkService.getMacAdress();
	}

    // ========== PASSKEY METRICS METHODS ==========

    /**
     * Record passkey registration attempt
     */
    public void recordPasskeyRegistrationAttempt(String userId, String deviceInfo, long startTime) {
        if (!isPasskeyMetricsEnabled()) {
            return;
        }
        
        CompletableFuture.runAsync(() -> {
            try {
                Map<String, Object> context = new HashMap<>();
                context.put("deviceInfo", deviceInfo);
                context.put("startTime", startTime);
                
                MetricEntry entry = createMetricEntry("PASSKEY_REGISTRATION_ATTEMPT", userId, true, 0, context);
                add(entry);
            } catch (Exception e) {
                // Log error but don't break the main flow
                System.err.println("Error recording passkey registration attempt: " + e.getMessage());
            }
        }, metricsExecutor);
    }

    /**
     * Record passkey registration success
     */
    public void recordPasskeyRegistrationSuccess(String userId, String deviceInfo, long duration) {
        if (!isPasskeyMetricsEnabled()) {
            return;
        }
        
        CompletableFuture.runAsync(() -> {
            try {
                Map<String, Object> context = new HashMap<>();
                context.put("deviceInfo", deviceInfo);
                context.put("duration", duration);
                
                MetricEntry entry = createMetricEntry("PASSKEY_REGISTRATION_SUCCESS", userId, true, duration, context);
                add(entry);
            } catch (Exception e) {
                System.err.println("Error recording passkey registration success: " + e.getMessage());
            }
        }, metricsExecutor);
    }

    /**
     * Record passkey registration failure
     */
    public void recordPasskeyRegistrationFailure(String userId, String deviceInfo, String errorReason, long duration) {
        if (!isPasskeyMetricsEnabled()) {
            return;
        }
        
        CompletableFuture.runAsync(() -> {
            try {
                Map<String, Object> context = new HashMap<>();
                context.put("deviceInfo", deviceInfo);
                context.put("errorReason", errorReason);
                context.put("duration", duration);
                
                MetricEntry entry = createMetricEntry("PASSKEY_REGISTRATION_FAILURE", userId, false, duration, context);
                add(entry);
            } catch (Exception e) {
                System.err.println("Error recording passkey registration failure: " + e.getMessage());
            }
        }, metricsExecutor);
    }

    /**
     * Record passkey authentication attempt
     */
    public void recordPasskeyAuthenticationAttempt(String userId, String deviceInfo, long startTime) {
        if (!isPasskeyMetricsEnabled()) {
            return;
        }
        
        CompletableFuture.runAsync(() -> {
            try {
                Map<String, Object> context = new HashMap<>();
                context.put("deviceInfo", deviceInfo);
                context.put("startTime", startTime);
                
                MetricEntry entry = createMetricEntry("PASSKEY_AUTHENTICATION_ATTEMPT", userId, true, 0, context);
                add(entry);
            } catch (Exception e) {
                System.err.println("Error recording passkey authentication attempt: " + e.getMessage());
            }
        }, metricsExecutor);
    }

    /**
     * Record passkey authentication success
     */
    public void recordPasskeyAuthenticationSuccess(String userId, String deviceInfo, long duration) {
        if (!isPasskeyMetricsEnabled()) {
            return;
        }
        
        CompletableFuture.runAsync(() -> {
            try {
                Map<String, Object> context = new HashMap<>();
                context.put("deviceInfo", deviceInfo);
                context.put("duration", duration);
                
                MetricEntry entry = createMetricEntry("PASSKEY_AUTHENTICATION_SUCCESS", userId, true, duration, context);
                add(entry);
            } catch (Exception e) {
                System.err.println("Error recording passkey authentication success: " + e.getMessage());
            }
        }, metricsExecutor);
    }

    /**
     * Record passkey authentication failure
     */
    public void recordPasskeyAuthenticationFailure(String userId, String deviceInfo, String errorReason, long duration) {
        if (!isPasskeyMetricsEnabled()) {
            return;
        }
        
        CompletableFuture.runAsync(() -> {
            try {
                Map<String, Object> context = new HashMap<>();
                context.put("deviceInfo", deviceInfo);
                context.put("errorReason", errorReason);
                context.put("duration", duration);
                
                MetricEntry entry = createMetricEntry("PASSKEY_AUTHENTICATION_FAILURE", userId, false, duration, context);
                add(entry);
            } catch (Exception e) {
                System.err.println("Error recording passkey authentication failure: " + e.getMessage());
            }
        }, metricsExecutor);
    }

    /**
     * Record passkey nudge shown
     */
    public void recordPasskeyNudgeShown(String userId, String context) {
        if (!isPasskeyMetricsEnabled()) {
            return;
        }
        
        CompletableFuture.runAsync(() -> {
            try {
                Map<String, Object> nudgeContext = new HashMap<>();
                nudgeContext.put("nudgeContext", context);
                
                MetricEntry entry = createMetricEntry("PASSKEY_NUDGE_SHOWN", userId, true, 0, nudgeContext);
                add(entry);
            } catch (Exception e) {
                System.err.println("Error recording passkey nudge shown: " + e.getMessage());
            }
        }, metricsExecutor);
    }

    /**
     * Record passkey nudge accepted
     */
    public void recordPasskeyNudgeAccepted(String userId, String context) {
        if (!isPasskeyMetricsEnabled()) {
            return;
        }
        
        CompletableFuture.runAsync(() -> {
            try {
                Map<String, Object> nudgeContext = new HashMap<>();
                nudgeContext.put("nudgeContext", context);
                
                MetricEntry entry = createMetricEntry("PASSKEY_NUDGE_ACCEPTED", userId, true, 0, nudgeContext);
                add(entry);
            } catch (Exception e) {
                System.err.println("Error recording passkey nudge accepted: " + e.getMessage());
            }
        }, metricsExecutor);
    }

    /**
     * Record passkey nudge declined
     */
    public void recordPasskeyNudgeDeclined(String userId, String context) {
        if (!isPasskeyMetricsEnabled()) {
            return;
        }
        
        CompletableFuture.runAsync(() -> {
            try {
                Map<String, Object> nudgeContext = new HashMap<>();
                nudgeContext.put("nudgeContext", context);
                
                MetricEntry entry = createMetricEntry("PASSKEY_NUDGE_DECLINED", userId, false, 0, nudgeContext);
                add(entry);
            } catch (Exception e) {
                System.err.println("Error recording passkey nudge declined: " + e.getMessage());
            }
        }, metricsExecutor);
    }

    /**
     * Record passkey fallback
     */
    public void recordPasskeyFallback(String userId, String fallbackMethod, String reason) {
        if (!isPasskeyMetricsEnabled()) {
            return;
        }
        
        CompletableFuture.runAsync(() -> {
            try {
                Map<String, Object> context = new HashMap<>();
                context.put("fallbackMethod", fallbackMethod);
                context.put("reason", reason);
                
                MetricEntry entry = createMetricEntry("PASSKEY_FALLBACK", userId, false, 0, context);
                add(entry);
            } catch (Exception e) {
                System.err.println("Error recording passkey fallback: " + e.getMessage());
            }
        }, metricsExecutor);
    }

    // ========== HELPER METHODS ==========

    /**
     * Check if passkey metrics are enabled
     */
    private boolean isPasskeyMetricsEnabled() {
        return appConfiguration.getPasskeyMetricsEnabled() != null && 
               appConfiguration.getPasskeyMetricsEnabled();
    }

    /**
     * Create a metric entry
     */
    private MetricEntry createMetricEntry(String eventType, String userId, boolean success, long duration, Map<String, Object> context) {
        // This is a placeholder - we'll implement proper MetricEntry creation in Issue #2
        // For now, we'll use the existing metric system
        MetricEntry entry = new MetricEntry();
        entry.setCreationDate(new Date());
        entry.setApplicationType(getApplicationType());
        entry.setNodeIndetifier(getNodeIndetifier());
        // Additional fields will be set in Issue #2
        return entry;
    }

    /**
     * Shutdown the metrics executor
     */
    public void shutdown() {
        if (metricsExecutor != null && !metricsExecutor.isShutdown()) {
            metricsExecutor.shutdown();
        }
    }
}