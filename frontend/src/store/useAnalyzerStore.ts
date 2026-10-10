import { useStore } from 'zustand';
import {
  analyzerStore,
  type AnalyzerState,
} from '../../../src/store/useAnalyzerStore.ts';

const useAnalyzerStoreHook = <T>(selector: (state: AnalyzerState) => T): T => {
  return useStore(analyzerStore, selector);
};

export const useAnalyzerStore = Object.assign(useAnalyzerStoreHook, analyzerStore);

export * from '../../../src/store/useAnalyzerStore.ts';
