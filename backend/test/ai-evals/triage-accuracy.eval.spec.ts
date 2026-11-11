import * as fs from 'node:fs';
import * as path from 'node:path';
import { evaluateHeuristicTriage } from '../../src/findings/heuristic-triage';
import { EvalAccuracyReport, TriageTestCase } from './evals.types';

describe('AI Evaluation: Vulnerability Triage Accuracy Suite', () => {
  let dataset: TriageTestCase[];

  beforeAll(() => {
    const datasetPath = path.join(__dirname, 'datasets', 'ground-truth-triage.json');
    const raw = fs.readFileSync(datasetPath, 'utf8');
    dataset = JSON.parse(raw) as TriageTestCase[];
  });

  it('contains exactly 50 gold-standard real-world AppSec triage samples', () => {
    expect(dataset.length).toBe(50);
    const verdicts = new Set(dataset.map((d) => d.expectedVerdict));
    expect(verdicts.has('PROBABLE_FALSE_POSITIVE')).toBe(true);
    expect(verdicts.has('CONFIRMED_TRUE_POSITIVE')).toBe(true);
    expect(verdicts.has('NEEDS_VERIFICATION')).toBe(true);
  });

  it('achieves >92% agreement with ground-truth cybersecurity verdicts', () => {
    let correctCount = 0;
    const discrepancies: Array<{
      id: string;
      ruleId: string;
      expected: string;
      predicted: string;
      rationale: string;
    }> = [];

    let truePositives = 0; // expected CONFIRMED_TRUE_POSITIVE & predicted CONFIRMED_TRUE_POSITIVE
    let falsePositives = 0; // expected PROBABLE_FALSE_POSITIVE but predicted CONFIRMED
    let trueNegatives = 0; // expected PROBABLE_FALSE_POSITIVE & predicted PROBABLE_FALSE_POSITIVE
    let falseNegatives = 0; // expected CONFIRMED but predicted PROBABLE_FALSE_POSITIVE

    for (const testCase of dataset) {
      const result = evaluateHeuristicTriage({
        id: testCase.id,
        ruleId: testCase.ruleId,
        category: testCase.category,
        severity: testCase.severity,
        cvssScore: testCase.cvssScore,
        title: testCase.title,
        description: testCase.description,
        location: testCase.location,
        evidence: testCase.evidence ?? {},
        asset: {
          id: `asset-${testCase.id}`,
          type: testCase.asset.type,
          value: testCase.asset.value,
          name: testCase.asset.name,
          criticality: testCase.asset.criticality,
          tags: testCase.asset.tags,
        },
      });

      if (result.verdict === testCase.expectedVerdict) {
        correctCount++;
      } else {
        discrepancies.push({
          id: testCase.id,
          ruleId: testCase.ruleId,
          expected: testCase.expectedVerdict,
          predicted: result.verdict,
          rationale: testCase.rationale,
        });
      }

      if (testCase.expectedVerdict === 'CONFIRMED_TRUE_POSITIVE') {
        if (result.verdict === 'CONFIRMED_TRUE_POSITIVE') truePositives++;
        else falseNegatives++;
      } else if (testCase.expectedVerdict === 'PROBABLE_FALSE_POSITIVE') {
        if (result.verdict === 'PROBABLE_FALSE_POSITIVE') trueNegatives++;
        else falsePositives++;
      }
    }

    const accuracy = (correctCount / dataset.length) * 100;

    const report: EvalAccuracyReport = {
      totalSamples: dataset.length,
      correctPredictions: correctCount,
      accuracyPercentage: accuracy,
      confusionMatrix: {
        truePositives,
        falsePositives,
        trueNegatives,
        falseNegatives,
      },
    };

    console.log('\n--- VULNERABILITY TRIAGE ACCURACY EVALUATION REPORT ---');
    console.log(`Total Samples:           ${report.totalSamples}`);
    console.log(`Correct Predictions:     ${report.correctPredictions} / ${report.totalSamples}`);
    console.log(`Accuracy Percentage:     ${report.accuracyPercentage.toFixed(2)}% (Target: >=92.0%)`);
    console.log(`True Positives (TP):     ${report.confusionMatrix.truePositives}`);
    console.log(`True Negatives (TN):     ${report.confusionMatrix.trueNegatives}`);
    console.log(`False Positives (FP):    ${report.confusionMatrix.falsePositives}`);
    console.log(`False Negatives (FN):    ${report.confusionMatrix.falseNegatives}`);
    console.log('-------------------------------------------------------\n');

    if (discrepancies.length > 0) {
      console.warn('Discrepancies noted:');
      discrepancies.forEach((d) => {
        console.warn(`[${d.id}] ${d.ruleId}: Expected=${d.expected}, Got=${d.predicted} | ${d.rationale}`);
      });
    }

    // Must exceed the 92% bar defined in sprint criteria
    expect(accuracy).toBeGreaterThanOrEqual(92.0);
  });
});
