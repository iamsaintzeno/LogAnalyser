import { attachParserWorker, createParserEngine, type ParserWorkerScope } from './parser.worker.ts';

attachParserWorker(globalThis as unknown as ParserWorkerScope, createParserEngine());
