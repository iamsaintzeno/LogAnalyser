import type {
  BlocklistRuleRow,
  LogEntryRow,
  ParsedLogSession,
  RuleOverride,
  ThreatEventRow,
} from '../contracts';

export interface DatabaseSchema {
  sessions: ParsedLogSession;
  entries: LogEntryRow;
  events: ThreatEventRow;
  blocklistRules: BlocklistRuleRow;
  ruleOverrides: RuleOverride;
}
