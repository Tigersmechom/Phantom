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
}

/** Groups are in backend-recorded order; stages within a group have no implied order. */
export interface ExpressionGroup { id: string; stages: ExpressionStage[] }
export interface ExpressionEvent extends ExpressionStage {
  line: number;
  groups?: ExpressionGroup[];
}
