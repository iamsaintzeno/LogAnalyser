// Re-export useLogAnalysis as useAnalyzeFile to match PROJECT_CONTEXT.md naming convention.
// The data path is: File → useAnalyzeFile hook → parser.worker.ts → postMessage → useAnalyzerStore → Dashboard.
export { useLogAnalysis as useAnalyzeFile } from './useLogAnalysis';
