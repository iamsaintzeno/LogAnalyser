import { installNetworkGuard } from '../lib/networkGuard.ts';
import { attachParserWorker, createParserEngine, type ParserWorkerScope } from './parser.worker.ts';

installNetworkGuard();
attachParserWorker(globalThis as unknown as ParserWorkerScope, createParserEngine());
