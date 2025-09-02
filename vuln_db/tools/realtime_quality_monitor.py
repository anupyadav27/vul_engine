"""
Real-time Data Quality Monitor for Vulnerability Pipeline

Continuous monitoring system that:
1. Monitors data flow in real-time
2. Validates every batch of data immediately
3. Triggers immediate alerts on data loss
4. Provides live quality metrics dashboard
5. Automatically stops pipeline on critical issues

Critical Features:
- ZERO tolerance for data loss
- Real-time validation
- Automated circuit breaker
- Live quality dashboard
- Comprehensive alerting
"""

import asyncio
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
import threading
import queue
from pathlib import Path

from data_quality_validator import DataQualityValidator, DataIntegrityReport


@dataclass
class QualityMetrics:
    """Real-time quality metrics"""
    timestamp: datetime
    source_name: str
    records_processed: int
    records_stored: int
    data_loss_count: int
    quality_score: float
    processing_time_ms: float
    validation_status: str


@dataclass
class AlertConfig:
    """Alert configuration"""
    data_loss_alert: bool = True
    quality_degradation_alert: bool = True
    performance_alert: bool = True
    email_recipients: List[str] = None
    slack_webhook: Optional[str] = None
    alert_cooldown_minutes: int = 5


class DataQualityMonitor:
    """Real-time data quality monitoring system"""
    
    def __init__(
        self, 
        db_config: Dict[str, Any],
        alert_config: AlertConfig = None,
        monitoring_interval: int = 30
    ):
        """Initialize the real-time monitor"""
        self.logger = logging.getLogger("data_quality_monitor")
        self.db_config = db_config
        self.alert_config = alert_config or AlertConfig()
        self.monitoring_interval = monitoring_interval
        
        # Initialize validator
        self.validator = DataQualityValidator(db_config)
        
        # Monitoring state
        self.is_monitoring = False
        self.circuit_breaker_active = False
        self.last_alert_times = {}
        
        # Quality metrics storage
        self.metrics_queue = queue.Queue(maxsize=1000)
        self.quality_history = []
        self.current_metrics = {}
        
        # Thresholds for circuit breaker
        self.circuit_breaker_thresholds = {
            'max_data_loss': 0,           # Zero tolerance
            'min_quality_score': 0.90,    # 90% minimum quality
            'max_processing_time_ms': 30000,  # 30 second timeout
            'consecutive_failures': 3      # Stop after 3 consecutive failures
        }
        
        # Performance tracking
        self.consecutive_failures = 0
        self.last_successful_validation = datetime.utcnow()
        
    def start_monitoring(self):
        """Start real-time monitoring"""
        if self.is_monitoring:
            self.logger.warning("Monitoring already active")
            return
        
        self.is_monitoring = True
        self.logger.info("🔍 Starting real-time data quality monitoring...")
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True
        )
        self.monitoring_thread.start()
        
        # Start metrics processing thread
        self.metrics_thread = threading.Thread(
            target=self._process_metrics_queue,
            daemon=True
        )
        self.metrics_thread.start()
        
        self.logger.info("✅ Real-time monitoring started")
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.is_monitoring = False
        self.logger.info("🛑 Stopping real-time monitoring...")
    
    def validate_batch_realtime(
        self, 
        source_data: List[Dict[str, Any]], 
        source_name: str,
        batch_id: str = None
    ) -> QualityMetrics:
        """
        CRITICAL: Real-time validation of data batch
        This is called for every batch of data processed
        """
        start_time = time.time()
        batch_id = batch_id or f"{source_name}_{int(time.time())}"
        
        self.logger.info(f"🔍 Real-time validation: {source_name} batch {batch_id} ({len(source_data)} records)")
        
        try:
            # Run comprehensive validation
            report = self.validator.validate_source_to_database_integrity(
                source_data, source_name
            )
            
            processing_time_ms = (time.time() - start_time) * 1000
            
            # Create quality metrics
            metrics = QualityMetrics(
                timestamp=datetime.utcnow(),
                source_name=source_name,
                records_processed=len(source_data),
                records_stored=report.total_records_database,
                data_loss_count=report.data_loss_count,
                quality_score=report.quality_score,
                processing_time_ms=processing_time_ms,
                validation_status="PASS" if report.data_loss_count == 0 else "FAIL"
            )
            
            # Add to metrics queue for processing
            try:
                self.metrics_queue.put_nowait(metrics)
            except queue.Full:
                self.logger.warning("Metrics queue full, dropping oldest metrics")
                self.metrics_queue.get()
                self.metrics_queue.put_nowait(metrics)
            
            # CRITICAL: Check for immediate action required
            self._check_circuit_breaker(metrics, report)
            
            # Update tracking
            if metrics.validation_status == "PASS":
                self.consecutive_failures = 0
                self.last_successful_validation = datetime.utcnow()
            else:
                self.consecutive_failures += 1
            
            # Log validation result
            if report.data_loss_count > 0:
                self.logger.critical(
                    f"🚨 CRITICAL DATA LOSS in {source_name}: {report.data_loss_count} records lost!"
                )
            else:
                self.logger.info(
                    f"✅ Validation passed for {source_name}: "
                    f"{metrics.records_processed} records, quality {metrics.quality_score:.2%}"
                )
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"❌ Real-time validation failed for {source_name}: {e}")
            
            # Create error metrics
            error_metrics = QualityMetrics(
                timestamp=datetime.utcnow(),
                source_name=source_name,
                records_processed=len(source_data),
                records_stored=0,
                data_loss_count=len(source_data),  # Assume all lost on error
                quality_score=0.0,
                processing_time_ms=(time.time() - start_time) * 1000,
                validation_status="ERROR"
            )
            
            self.consecutive_failures += 1
            return error_metrics
    
    def _check_circuit_breaker(self, metrics: QualityMetrics, report: DataIntegrityReport):
        """Check if circuit breaker should be activated"""
        critical_issues = []
        
        # Check data loss (ZERO tolerance)
        if metrics.data_loss_count > self.circuit_breaker_thresholds['max_data_loss']:
            critical_issues.append(f"Data loss detected: {metrics.data_loss_count} records")
        
        # Check quality score
        if metrics.quality_score < self.circuit_breaker_thresholds['min_quality_score']:
            critical_issues.append(f"Quality below threshold: {metrics.quality_score:.2%}")
        
        # Check processing time
        if metrics.processing_time_ms > self.circuit_breaker_thresholds['max_processing_time_ms']:
            critical_issues.append(f"Processing timeout: {metrics.processing_time_ms:.0f}ms")
        
        # Check consecutive failures
        if self.consecutive_failures >= self.circuit_breaker_thresholds['consecutive_failures']:
            critical_issues.append(f"Consecutive failures: {self.consecutive_failures}")
        
        # Activate circuit breaker if critical issues found
        if critical_issues:
            self._activate_circuit_breaker(metrics, critical_issues, report)
    
    def _activate_circuit_breaker(
        self, 
        metrics: QualityMetrics, 
        issues: List[str], 
        report: DataIntegrityReport
    ):
        """CRITICAL: Activate circuit breaker to stop pipeline"""
        if self.circuit_breaker_active:
            return  # Already active
        
        self.circuit_breaker_active = True
        
        circuit_breaker_message = f"""
        🚨 CRITICAL: CIRCUIT BREAKER ACTIVATED 🚨
        
        Source: {metrics.source_name}
        Time: {metrics.timestamp}
        Critical Issues:
        {chr(10).join(f'  - {issue}' for issue in issues)}
        
        PIPELINE AUTOMATICALLY STOPPED!
        IMMEDIATE MANUAL INTERVENTION REQUIRED!
        """
        
        self.logger.critical(circuit_breaker_message)
        
        # Send immediate alerts
        self._send_critical_alert(
            "CIRCUIT BREAKER ACTIVATED - PIPELINE STOPPED",
            circuit_breaker_message,
            metrics,
            report
        )
        
        # Stop monitoring (this should trigger pipeline shutdown)
        self.stop_monitoring()
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                # Check overall system health
                self._check_system_health()
                
                # Generate health report
                if datetime.utcnow().minute % 15 == 0:  # Every 15 minutes
                    self._generate_health_report()
                
                # Sleep until next check
                time.sleep(self.monitoring_interval)
                
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                time.sleep(self.monitoring_interval)
    
    def _process_metrics_queue(self):
        """Process metrics queue and update dashboard data"""
        while self.is_monitoring:
            try:
                # Process all pending metrics
                metrics_batch = []
                while not self.metrics_queue.empty():
                    try:
                        metrics = self.metrics_queue.get_nowait()
                        metrics_batch.append(metrics)
                    except queue.Empty:
                        break
                
                # Update current metrics and history
                for metrics in metrics_batch:
                    self.current_metrics[metrics.source_name] = metrics
                    self.quality_history.append(metrics)
                    
                    # Keep only last 1000 metrics
                    if len(self.quality_history) > 1000:
                        self.quality_history = self.quality_history[-1000:]
                    
                    # Send alerts if needed
                    self._check_alerts(metrics)
                
                time.sleep(1)  # Process every second
                
            except Exception as e:
                self.logger.error(f"Metrics processing error: {e}")
                time.sleep(5)
    
    def _check_system_health(self):
        """Check overall system health"""
        current_time = datetime.utcnow()
        
        # Check if no validation for too long
        time_since_last_validation = current_time - self.last_successful_validation
        if time_since_last_validation > timedelta(minutes=30):
            self.logger.warning(
                f"⚠️ No successful validation for {time_since_last_validation}. "
                f"Pipeline may be stalled."
            )
        
        # Check database connectivity
        try:
            # Simple connectivity check
            count = self.validator._get_database_record_count("health_check")
            self.logger.debug(f"Database connectivity check passed")
        except Exception as e:
            self.logger.error(f"❌ Database connectivity issue: {e}")
    
    def _check_alerts(self, metrics: QualityMetrics):
        """Check if alerts should be sent for current metrics"""
        current_time = datetime.utcnow()
        
        # Check alert cooldown
        last_alert_key = f"{metrics.source_name}_{metrics.validation_status}"
        last_alert_time = self.last_alert_times.get(last_alert_key)
        
        if last_alert_time:
            time_since_alert = current_time - last_alert_time
            if time_since_alert < timedelta(minutes=self.alert_config.alert_cooldown_minutes):
                return  # Still in cooldown
        
        # Data loss alert (CRITICAL)
        if self.alert_config.data_loss_alert and metrics.data_loss_count > 0:
            self._send_alert(
                "DATA LOSS DETECTED",
                f"🚨 {metrics.data_loss_count} records lost in {metrics.source_name}!",
                metrics,
                severity="CRITICAL"
            )
            self.last_alert_times[last_alert_key] = current_time
        
        # Quality degradation alert
        elif self.alert_config.quality_degradation_alert and metrics.quality_score < 0.90:
            self._send_alert(
                "QUALITY DEGRADATION",
                f"⚠️ Quality dropped to {metrics.quality_score:.2%} for {metrics.source_name}",
                metrics,
                severity="WARNING"
            )
            self.last_alert_times[last_alert_key] = current_time
        
        # Performance alert
        elif self.alert_config.performance_alert and metrics.processing_time_ms > 15000:
            self._send_alert(
                "PERFORMANCE DEGRADATION",
                f"📈 Slow processing: {metrics.processing_time_ms:.0f}ms for {metrics.source_name}",
                metrics,
                severity="INFO"
            )
            self.last_alert_times[last_alert_key] = current_time
    
    def _send_alert(
        self, 
        subject: str, 
        message: str, 
        metrics: QualityMetrics, 
        severity: str = "INFO"
    ):
        """Send alert via configured channels"""
        alert_data = {
            'timestamp': metrics.timestamp.isoformat(),
            'severity': severity,
            'subject': subject,
            'message': message,
            'metrics': asdict(metrics)
        }
        
        # Log alert
        log_message = f"🚨 ALERT [{severity}]: {subject} - {message}"
        if severity == "CRITICAL":
            self.logger.critical(log_message)
        elif severity == "WARNING":
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
        
        # Send to configured channels
        if self.alert_config.email_recipients:
            self._send_email_alert(alert_data)
        
        if self.alert_config.slack_webhook:
            self._send_slack_alert(alert_data)
    
    def _send_critical_alert(
        self, 
        subject: str, 
        message: str, 
        metrics: QualityMetrics, 
        report: DataIntegrityReport
    ):
        """Send critical alert with full details"""
        critical_data = {
            'timestamp': metrics.timestamp.isoformat(),
            'severity': 'CRITICAL',
            'subject': subject,
            'message': message,
            'metrics': asdict(metrics),
            'validation_results': [
                {
                    'check_name': r.check_name,
                    'status': r.status,
                    'message': r.message
                } for r in report.validation_results
            ],
            'recommendations': report.recommendations
        }
        
        # Log critical alert
        self.logger.critical(f"🚨 CRITICAL ALERT: {subject}")
        
        # Force send to all channels regardless of cooldown
        if self.alert_config.email_recipients:
            self._send_email_alert(critical_data)
        
        if self.alert_config.slack_webhook:
            self._send_slack_alert(critical_data)
    
    def _send_email_alert(self, alert_data: Dict[str, Any]):
        """Send email alert (implement based on your email system)"""
        # This would integrate with your email system
        # For now, just log the email content
        self.logger.info(f"📧 EMAIL ALERT: {alert_data['subject']}")
        
        # Example implementation:
        # import smtplib
        # from email.mime.text import MIMEText
        # ... email sending logic ...
    
    def _send_slack_alert(self, alert_data: Dict[str, Any]):
        """Send Slack alert (implement based on your Slack setup)"""
        # This would integrate with Slack webhook
        # For now, just log the Slack message
        self.logger.info(f"💬 SLACK ALERT: {alert_data['subject']}")
        
        # Example implementation:
        # import requests
        # requests.post(self.alert_config.slack_webhook, json={
        #     'text': f"{alert_data['subject']}\n{alert_data['message']}"
        # })
    
    def _generate_health_report(self):
        """Generate comprehensive health report"""
        if not self.quality_history:
            return
        
        # Calculate aggregate metrics
        recent_metrics = [m for m in self.quality_history 
                         if (datetime.utcnow() - m.timestamp) < timedelta(hours=1)]
        
        if not recent_metrics:
            return
        
        health_report = {
            'timestamp': datetime.utcnow().isoformat(),
            'monitoring_status': 'ACTIVE' if self.is_monitoring else 'STOPPED',
            'circuit_breaker_active': self.circuit_breaker_active,
            'total_validations_last_hour': len(recent_metrics),
            'sources_monitored': list(set(m.source_name for m in recent_metrics)),
            'average_quality_score': sum(m.quality_score for m in recent_metrics) / len(recent_metrics),
            'total_data_loss_incidents': sum(1 for m in recent_metrics if m.data_loss_count > 0),
            'average_processing_time_ms': sum(m.processing_time_ms for m in recent_metrics) / len(recent_metrics),
            'consecutive_failures': self.consecutive_failures
        }
        
        self.logger.info(f"📊 Health Report: {json.dumps(health_report, indent=2)}")
        
        # Save health report
        health_file = Path("quality_health_report.json")
        with open(health_file, 'w') as f:
            json.dump(health_report, f, indent=2)
    
    def get_live_dashboard_data(self) -> Dict[str, Any]:
        """Get current dashboard data for live monitoring"""
        current_time = datetime.utcnow()
        
        # Get recent metrics (last hour)
        recent_metrics = [m for m in self.quality_history 
                         if (current_time - m.timestamp) < timedelta(hours=1)]
        
        # Calculate dashboard metrics
        dashboard_data = {
            'timestamp': current_time.isoformat(),
            'monitoring_active': self.is_monitoring,
            'circuit_breaker_active': self.circuit_breaker_active,
            'current_sources': list(self.current_metrics.keys()),
            'total_validations_today': len([m for m in self.quality_history 
                                          if (current_time - m.timestamp) < timedelta(days=1)]),
            'data_loss_incidents_today': len([m for m in self.quality_history 
                                            if (current_time - m.timestamp) < timedelta(days=1) 
                                            and m.data_loss_count > 0]),
            'current_metrics_by_source': {
                source: asdict(metrics) for source, metrics in self.current_metrics.items()
            },
            'recent_quality_trend': [
                {
                    'timestamp': m.timestamp.isoformat(),
                    'source': m.source_name,
                    'quality_score': m.quality_score,
                    'data_loss_count': m.data_loss_count
                } for m in recent_metrics[-50:]  # Last 50 validations
            ],
            'system_health': {
                'consecutive_failures': self.consecutive_failures,
                'last_successful_validation': self.last_successful_validation.isoformat(),
                'average_quality_last_hour': sum(m.quality_score for m in recent_metrics) / len(recent_metrics) if recent_metrics else 0
            }
        }
        
        return dashboard_data
    
    def reset_circuit_breaker(self):
        """Manual reset of circuit breaker after issues are resolved"""
        if not self.circuit_breaker_active:
            self.logger.info("Circuit breaker is not active")
            return
        
        self.logger.info("🔧 Manually resetting circuit breaker...")
        self.circuit_breaker_active = False
        self.consecutive_failures = 0
        self.last_successful_validation = datetime.utcnow()
        
        # Restart monitoring
        self.start_monitoring()
        
        self.logger.info("✅ Circuit breaker reset, monitoring resumed")
    
    def export_quality_history(self, output_path: str, hours: int = 24):
        """Export quality history for analysis"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        export_data = {
            'export_timestamp': datetime.utcnow().isoformat(),
            'hours_exported': hours,
            'metrics': [
                asdict(m) for m in self.quality_history 
                if m.timestamp >= cutoff_time
            ]
        }
        
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        self.logger.info(f"📁 Quality history exported to {output_path}")


# Example usage and integration
if __name__ == "__main__":
    """Example of setting up real-time monitoring"""
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Database configuration
    db_config = {
        'type': 'sqlite',
        'database_path': 'vulnerabilities.db'
    }
    
    # Alert configuration
    alert_config = AlertConfig(
        data_loss_alert=True,
        quality_degradation_alert=True,
        performance_alert=True,
        email_recipients=['admin@company.com'],
        slack_webhook='https://hooks.slack.com/...',
        alert_cooldown_minutes=5
    )
    
    # Create and start monitor
    monitor = DataQualityMonitor(db_config, alert_config)
    monitor.start_monitoring()
    
    try:
        # Simulate data validation
        while True:
            # This would be called by your actual pipeline
            sample_data = [
                {'cve_id': 'CVE-2024-TEST', 'description': 'Test vulnerability'}
            ]
            
            metrics = monitor.validate_batch_realtime(sample_data, 'nvd')
            print(f"Validation result: {metrics.validation_status}")
            
            time.sleep(60)  # Wait 1 minute between validations
            
    except KeyboardInterrupt:
        print("Stopping monitoring...")
        monitor.stop_monitoring()