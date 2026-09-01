global class ClaudeTestReportExportCondition implements TxnSecurity.EventCondition {
    // Alert-only test condition: true when a report is exported.
    public Boolean evaluate(SObject event) {
        if (event instanceof ReportEvent) {
            return ((ReportEvent) event).Operation == 'ReportExported';
        }
        return false;
    }
}
