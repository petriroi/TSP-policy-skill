@isTest
private class ClaudeTestReportExportConditionTest {
    @isTest static void firesOnExport() {
        ClaudeTestReportExportCondition c = new ClaudeTestReportExportCondition();
        System.assertEquals(true,  c.evaluate(new ReportEvent(Operation='ReportExported')));
        System.assertEquals(false, c.evaluate(new ReportEvent(Operation='ReportRunFromLightning')));
    }
}
