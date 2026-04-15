'use strict';

const express = require('express');
const shieldwall = require('../src/index');
const path = require('path');

const app = express();
app.use(express.json());

const waf = shieldwall({
  mode: 'block',
  reporting: {
    enabled: true,
    reportsDir: path.join(__dirname, 'reports'),
    maxStoredReports: 6,
  },
  logLevel: 'info',
});

// Report event handler
waf.on('report', ({ type, report, filepath }) => {
  console.log(`\n=== ${type === '14d' ? '14-day' : 'Monthly'} report generated ===`);
  console.log(`File: ${filepath}`);
  console.log(`Total attacks: ${report.summary.totalAttacks}`);
  console.log(`Blocked: ${report.summary.blocked} (${report.summary.blockRate}%)`);

  if (report.extended?.roi) {
    const r = report.extended.roi;
    console.log(`\nResource savings:`);
    console.log(`  Traffic saved: ${r.trafficSavedGB} GB`);
    console.log(`  CPU time: ${r.cpuTimeSavedHours} hours`);
    console.log(`  Est. cost saved: ${r.estimatedCostSaved}`);
  }

  if (report.extended?.persistentAttackers?.length > 0) {
    console.log(`\nPersistent attackers:`);
    report.extended.persistentAttackers.forEach(p => {
      console.log(`  🔴 ${p.ip}: ${p.periodsActive} periods, ${p.attackCategories.join(', ')}`);
    });
  }

  if (report.extended?.vectorShift?.shifts?.length > 0) {
    console.log(`\nAttack vector shifts:`);
    report.extended.vectorShift.shifts.forEach(s => {
      console.log(`  ${s.category}: ${s.direction} (${s.change})`);
    });
  }

  if (report.recommendations.length > 0) {
    console.log('\nRecommendations:');
    report.recommendations.slice(0, 3).forEach(r => {
      console.log(`  [${r.priority.toUpperCase()}] ${r.message}`);
      console.log(`           → ${r.action}`);
    });
  }

  if (report.comparison) {
    console.log(`\nTrend: ${report.comparison.trend}`);
    console.log(`  Attack change: ${report.comparison.attacksChange}`);
  }
});

app.use(waf);

// Manual report endpoint
app.get('/admin/report', (req, res) => {
  const days = parseInt(req.query.days) || 14;
  const report = waf.getReport(days);
  
  if (!report) {
    return res.status(503).json({ error: 'Reporting not available' });
  }
  
  res.json({
    period: `${days} days`,
    generated: report.generatedAt,
    summary: report.summary,
    topThreats: report.topThreats,
    recommendations: report.recommendations,
    comparison: report.comparison,
  });
});

// Stored reports list
app.get('/admin/reports', (req, res) => {
  const reports = waf.getStoredReports();
  res.json(reports.map(r => ({
    period: r.period,
    generated: r.generatedAt,
    attacks: r.summary.totalAttacks,
    trend: r.comparison?.trend || 'unknown',
  })));
});

// SVG chart for latest monthly report
app.get('/admin/chart.svg', (req, res) => {
  const reports = waf.getStoredReports().filter(r => r.period === 'monthly');
  if (!reports.length || !reports[0].extended?.chartSVG) {
    return res.status(404).send('No chart available');
  }
  res.setHeader('Content-Type', 'image/svg+xml');
  res.send(reports[0].extended.chartSVG);
});

// Test endpoints that generate traffic
app.get('/api/users', (req, res) => res.json({ users: [] }));
app.post('/api/login', (req, res) => res.json({ token: 'test' }));
app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.listen(3000, () => {
  console.log('Server with reporting on http://localhost:3000');
  console.log('Reports will be auto-generated every 14 days and monthly');
  console.log('Manual report: GET /admin/report?days=14');
  console.log('Stored reports: GET /admin/reports');
});
