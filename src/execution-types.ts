/** Source coordinates supplied by the execution adapter: 1-based, end exclusive. */
export interface SourcePosition { line: number; column: number }
export interface SourceRange { start: SourcePosition; end: SourcePosition }
export type ExpressionOperator =
  | '+' | '-' | '*' | '/' | '%'
  | '<' | '>' | '<=' | '>=' | '==' | '!=' | '<=>'
  | '&' | '|' | '^' | '~' | '!' | '&&' | '||' | '<<' | '>>'
  | '=' | '+=' | '-=' | '*=' | '/=' | '%=' | '&=' | '|=' | '^=' | '<<=' | '>>='
  | '++' | '--' | '?:' | ',' | '[]' | '.' | '->'
  | 'call' | 'return' | 'input' | 'output';
/** Exact integer/float text from the backend must remain text throughout rendering. */
export type ExpressionValue = number | string | null;

/**
 * Runtime control-flow facts recorded by an execution adapter. These are
 * observations of the path that was taken, not guesses from source text.
 * `condition` is optional because a debugger can stop at a branch without
 * observing the value that selected it.
 */
export type RuntimeControlKind =
  | "if"
  | "else"
  | "loop"
  | "switch"
  | "case"
  | "default"
  | "break"
  | "continue"
  | "goto"
  | "throw"
  | "catch"
  | "rethrow"
  | "return"
  | "fallthrough"
  | "cleanup";
export type RuntimeControlPhase =
  | "before"
  | "condition"
  | "taken"
  | "enter"
  | "leave"
  | "unwind"
  | "caught"
  | "terminate"
  | "fallthrough";
export type RuntimeControlCondition = "true" | "false" | "case" | "default" | "unknown";
export interface RuntimeControlEvent {
  id: string;
  kind: RuntimeControlKind;
  phase: RuntimeControlPhase;
  line: number;
  range?: SourceRange;
  /** Destination for a taken branch, jump, break/continue, or catch. */
  targetLine?: number;
  targetRange?: SourceRange;
  condition?: ExpressionValue;
  conditionKind?: "boolean" | "integer" | "unknown";
  branch?: RuntimeControlCondition;
  /** Exception identity is stable through throw/search/unwind/catch. */
  exceptionId?: string;
  exceptionType?: string;
  /** The adapter may report the cleanup path without pretending it saw all frames. */
  activationId?: string;
  fromActivationId?: string;
  toActivationId?: string;
  observed: boolean;
}

/** Primitive globals/statics read by an expression, including their declaration location. */
export interface GlobalReference {
  id: string;
  name: string;
  qualifiedName?: string;
  type: string;
  value: ExpressionValue;
  scope: "global" | "static" | "thread-local";
  locator?: string;
  useRange?: SourceRange;
  declarationRange?: SourceRange;
}

/** Values are observed results, never inferred by the renderer from source text. */
export interface ExpressionStage {
  id: string;
  operands: ExpressionValue[];
  operator: ExpressionOperator;
  result: ExpressionValue;
  label: string;
  target?: string;
  range?: SourceRange;
  operandRanges?: SourceRange[];
  /** Exact operand names/source excerpts, aligned with operands; never parsed from a call label. */
  operandLabels?: string[];
  /** Supplied semantic type: overloaded comparison operators need not return bool. */
  resultKind?: 'boolean';
  /** Exact global/static primitive reads observed for this stage. */
  globalReferences?: GlobalReference[];
}

/** Groups are in backend-recorded order; stages within a group have no implied order. */
export interface ExpressionGroup { id: string; stages: ExpressionStage[] }
export interface ExpressionEvent extends ExpressionStage {
  line: number;
  groups?: ExpressionGroup[];
}
