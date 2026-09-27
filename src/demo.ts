import type { ExpressionEvent, ExpressionOperator, SourceRange } from './execution-types';
import type { InputTrace } from './backend-contract';

export const DEMO_SOURCE = `#include <iostream>
#include <vector>

int add(int a, int b) {
    return a + b;
}

int main() {
    const int n = 6;
    std::vector<int> values(n);
    for (auto& value : values)
        std::cin >> value;
    std::vector<int> prefix(n + 1, 0);

    for (int i = 0; i < n; ++i) {
        prefix[i + 1] = add(prefix[i], values[i]);
    }
    std::cout << "sum = " << prefix[n] << '\\n';
    return 0;
}`;
export const DEFAULT_INPUT = "3  1  4  1  5  9";
export const DEMO_FRAME_COUNT = 57;
export function parseInput(value: string): number[] | null {
  const parts = value.trim().split(/\s+/);
  if (parts.length !== 6 || parts.some((s) => !/^-?\d+$/.test(s))) return null;
  const numbers = parts.map(Number);
  return numbers.every((n) => Number.isSafeInteger(n) && Math.abs(n) <= 1000000)
    ? numbers
    : null;
}
/** Known token extractions of this prepared demo only; never a parser for arbitrary C++ stdin. */
export function demoInputTrace(step: number, submittedInput: string): InputTrace {
  if (!parseInput(submittedInput)) return { revision: submittedInput, consumedRanges: [], status: 'error' };
  const frame = Number.isFinite(step) ? Math.max(0, Math.min(DEMO_FRAME_COUNT - 1, Math.floor(step))) : 0;
  // match.index and token.length are UTF-16 offsets. Preserve all original whitespace.
  const tokens = [...submittedInput.matchAll(/\S+/gu)].map(match => ({ start: match.index, end: match.index + match[0].length }));
  const readCount = frame < 4 ? 0 : Math.min(6, Math.floor((frame - 4) / 2) + 1);
  const active = frame >= 3 && frame <= 13 && frame % 2 === 1 ? tokens[(frame - 3) / 2] : undefined;
  return {
    revision: submittedInput,
    consumedRanges: tokens.slice(0, readCount),
    ...(active ? { activeRange: active } : {}),
    status: frame < 3 ? 'idle' : readCount === 6 ? 'complete' : 'reading',
  };
}
export type DemoPhase = 'entry' | 'declaration' | 'allocation' | 'input-binding' | 'input' | 'input-end' | 'loop-init' | 'condition' | 'call' | 'callee-entry' | 'evaluate' | 'store' | 'increment' | 'output' | 'return';
export interface DemoSnapshot {
  i: number | null;
  n: number | null;
  inLoop: boolean;
  filled: number;
  arrayValues: (number | null)[];
  prefix: (number | null)[];
  sum: number | null;
  line: number;
  functionName: string;
  done: boolean;
  expression: ExpressionEvent | null;
  initialized: { n: boolean; values: boolean; prefix: boolean; i: boolean };
  phase: DemoPhase;
  label: string;
  inputIndex: number | null;
  readCount: number;
  a: number | null;
  b: number | null;
  output: string | null;
}

const add = (a: number | null, b: number | null) => a === null || b === null ? null : a + b;
const demoExpressionSpans: Record<string, { text: string; operands: string[]; resultKind?: 'boolean' }> = {
  '9:=': { text: 'n = 6', operands: ['6'] },
  '12:input': { text: 'std::cin >> value', operands: ['value'] },
  '13:+': { text: 'n + 1', operands: ['n', '1'] },
  '15:=': { text: 'i = 0', operands: ['0'] },
  '15:<': { text: 'i < n', operands: ['i', 'n'], resultKind: 'boolean' },
  '15:++': { text: '++i', operands: ['i'] },
  '16:call': { text: 'add(prefix[i], values[i])', operands: ['prefix[i]', 'values[i]'] },
  '5:+': { text: 'a + b', operands: ['a', 'b'] },
  '16:=': { text: 'prefix[i + 1] = add(prefix[i], values[i])', operands: ['add(prefix[i], values[i])'] },
  '18:output': { text: 'prefix[n]', operands: ['prefix[n]'] },
  '19:return': { text: 'return 0', operands: ['0'] },
};
/** Static annotations of DEMO_SOURCE, not a C++ expression recognizer. */
function demoExpressionRanges(line: number, operator: ExpressionOperator): Pick<ExpressionEvent, 'range' | 'operandRanges' | 'operandLabels' | 'resultKind'> {
  const annotation = demoExpressionSpans[`${line}:${operator}`];
  if (!annotation) return {};
  const start = DEMO_SOURCE.split('\n')[line - 1].indexOf(annotation.text);
  const range = (offset: number, length: number): SourceRange => ({ start: { line, column: offset + 1 }, end: { line, column: offset + length + 1 } });
  if (start < 0) throw Error(`Prepared demo annotation no longer matches line ${line}`);
  let after = 0;
  const operandRanges = annotation.operands.map(text => {
    const offset = annotation.text.indexOf(text, after);
    if (offset < 0) throw Error(`Prepared operand annotation no longer matches line ${line}`);
    after = offset + text.length;
    return range(start + offset, text.length);
  });
  return {
    range: range(start, annotation.text.length), operandRanges, operandLabels: [...annotation.operands],
    ...(annotation.resultKind ? { resultKind: annotation.resultKind } : {}),
  };
}

/**
 * Prepared, deterministic trace of DEMO_SOURCE only, not a C++ interpreter or LLDB.
 * Each snapshot records the indicated operation's completed state. Null slots are
 * unavailable placeholders before allocation; vector<int>(n) genuinely creates zeros.
 */
export function snapshot(step: number, values: number[]): DemoSnapshot {
  const bounded = Number.isFinite(step) ? Math.max(0, Math.min(DEMO_FRAME_COUNT - 1, Math.floor(step))) : 0;
  const state: DemoSnapshot = {
    i: null, n: null, inLoop: false, filled: 0,
    arrayValues: Array<number | null>(6).fill(null), prefix: Array<number | null>(7).fill(null),
    sum: null, line: 8, functionName: 'main()', done: false, expression: null,
    initialized: { n: false, values: false, prefix: false, i: false },
    phase: 'entry', label: 'Вход в main()', inputIndex: null, readCount: 0, a: null, b: null, output: null,
  };
  const event = (frame: number, line: number, operator: ExpressionOperator, operands: (number | null)[], result: number | null, label: string, target?: string): ExpressionEvent => ({ id: `demo:${frame}`, line, operator, operands, result, label, ...(target ? { target } : {}), ...demoExpressionRanges(line, operator) });
  const move = (line: number, phase: DemoPhase, label: string, expression: ExpressionEvent | null = null) => {
    state.line = line; state.phase = phase; state.label = label; state.expression = expression;
  };
  for (let frame = 1; frame <= bounded; frame++) {
    if (frame === 1) {
      state.n = 6; state.initialized.n = true;
      move(9, 'declaration', 'Объявление n = 6', event(frame, 9, '=', [6], 6, 'n = 6', 'n'));
    } else if (frame === 2) {
      state.arrayValues.fill(0); state.initialized.values = true;
      move(10, 'allocation', 'Создание values: 6 нулевых элементов');
    } else if (frame >= 3 && frame <= 14) {
      const index = Math.floor((frame - 3) / 2);
      state.inputIndex = index;
      if (frame % 2 === 1) move(11, 'input-binding', `value ссылается на values[${index}]`);
      else {
        const value = values[index];
        const observed = Number.isSafeInteger(value) && Math.abs(value) <= 1_000_000 ? value : null;
        state.arrayValues[index] = observed; state.readCount = index + 1;
        move(12, 'input', `Ввод values[${index}]`, event(frame, 12, 'input', [observed], observed, `cin → values[${index}]`, `values[${index}]`));
      }
    } else if (frame === 15) {
      state.inputIndex = null;
      move(11, 'input-end', 'Ввод всех элементов завершён');
    } else if (frame === 16) {
      state.prefix.fill(0); state.sum = 0; state.initialized.prefix = true;
      move(13, 'allocation', 'Создание prefix: 7 нулевых элементов', event(frame, 13, '+', [state.n, 1], 7, 'n + 1', 'prefix.size()'));
    } else if (frame === 17) {
      state.i = 0; state.inLoop = true; state.initialized.i = true;
      move(15, 'loop-init', 'Объявление i = 0', event(frame, 15, '=', [0], 0, 'i = 0', 'i'));
    } else if (frame >= 18 && frame <= 53) {
      const index = Math.floor((frame - 18) / 6), phase = (frame - 18) % 6;
      const a = state.prefix[index], b = state.arrayValues[index], result = add(a, b);
      if (phase === 0) move(15, 'condition', `Проверка ${index} < 6: true`, event(frame, 15, '<', [index, state.n], 1, 'i < n'));
      else if (phase === 1) move(16, 'call', `Вызов add для prefix[${index + 1}]`, event(frame, 16, 'call', [a, b], null, 'add(prefix[i], values[i])', `prefix[${index + 1}]`));
      else if (phase === 2) {
        state.functionName = 'add(a, b)'; state.a = a; state.b = b;
        move(4, 'callee-entry', 'Вход в add: параметры a и b доступны');
      } else if (phase === 3) {
        move(5, 'evaluate', 'Вычисление a + b и возврат результата', event(frame, 5, '+', [a, b], result, 'a + b', 'return'));
      } else if (phase === 4) {
        state.functionName = 'main()'; state.a = null; state.b = null;
        state.prefix[index + 1] = result; state.filled = index + 1; state.sum = result;
        move(16, 'store', `Результат add записан в prefix[${index + 1}]`, event(frame, 16, '=', [result], result, 'Результат add → prefix[i + 1]', `prefix[${index + 1}]`));
      } else {
        state.i = index + 1;
        move(15, 'increment', `Увеличение i: ${index} → ${index + 1}`, event(frame, 15, '++', [index], index + 1, '++i', 'i'));
      }
    } else if (frame === 54) {
      move(15, 'condition', 'Проверка 6 < 6: false', event(frame, 15, '<', [6, state.n], 0, 'i < n'));
    } else if (frame === 55) {
      state.i = null; state.inLoop = false; state.initialized.i = false;
      state.output = state.sum === null ? null : `sum = ${state.sum}\n`;
      move(18, 'output', 'Вывод prefix[n]', event(frame, 18, 'output', [state.sum], state.sum, 'cout << prefix[n]'));
    } else {
      state.done = true;
      move(19, 'return', 'Возврат 0 из main()', event(frame, 19, 'return', [0], 0, 'return 0'));
    }
  }
  return state;
}
