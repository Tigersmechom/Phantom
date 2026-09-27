/** Lexical C++ colour preview. Semantic highlighting will come from the language server. */
export type TokenType = 'plain' | 'keyword' | 'string' | 'number' | 'comment' | 'preprocessor' | 'type' | 'function' | 'variable' | 'systemFunction' | 'declaration';
export type CodeToken = { text: string; type: TokenType };

const keywords = new Set('alignas alignof asm auto bool break case catch char char8_t char16_t char32_t class concept const consteval constexpr constinit const_cast continue co_await co_return co_yield decltype default delete do double dynamic_cast else enum explicit export extern false float for friend goto if inline int long mutable namespace new noexcept nullptr operator private protected public register reinterpret_cast requires return short signed sizeof static static_assert static_cast struct switch template this thread_local throw true try typedef typeid typename union unsigned using virtual void volatile wchar_t while'.split(' '));
const types = new Set('std string string_view vector array map unordered_map set unordered_set list deque queue stack pair tuple optional unique_ptr shared_ptr size_t ptrdiff_t ostream istream iterator'.split(' '));
const systemFunctions = new Set('printf scanf puts putchar getchar getline sort min max move forward make_unique make_shared accumulate begin end size empty push_back emplace_back reserve resize clear erase insert find swap sqrt pow abs sin cos floor ceil round'.split(' '));
const systemVariables = new Set('cout cin cerr clog endl'.split(' '));
const tokenPattern = /\/\/.*|\/\*.*?(?:\*\/|$)|(?:u8|u|U|L)?"(?:\\.|[^"\\])*"?|(?:u8|u|U|L)?'(?:\\.|[^'\\])*'?|#[ \t]*[A-Za-z_]+|\b(?:0[xX][\da-fA-F']+(?:\.[\da-fA-F']*)?(?:[pP][+-]?\d+)?|0[bB][01']+|(?:\d[\d']*(?:\.[\d']*)?|\.\d+)(?:[eE][+-]?\d+)?)[uUlLfF]*\b|[A-Za-z_]\w*|\s+|./g;

export function tokenizeLine(line: string): CodeToken[] {
  const pieces = line.match(tokenPattern) ?? [];
  const preprocessor = /^\s*#/.test(line);
  return pieces.map((text, index) => {
    let type: TokenType = 'plain';
    const next = pieces.slice(index + 1).find(part => part.trim());
    if (text.startsWith('//') || text.startsWith('/*')) type = 'comment';
    else if (/^(?:u8|u|U|L)?["']/.test(text)) type = 'string';
    else if (text.startsWith('#')) type = 'preprocessor';
    else if (/^(?:\d|\.\d)/.test(text)) type = 'number';
    else if (keywords.has(text)) type = 'keyword';
    else if (types.has(text) || /^[A-Z][A-Za-z0-9]*[a-z][A-Za-z0-9]*$/.test(text)) type = 'type';
    else if (systemVariables.has(text)) type = 'systemFunction';
    else if (/^[A-Za-z_]\w*$/.test(text)) {
      if (preprocessor) type = 'preprocessor';
      else if (next === '(') type = systemFunctions.has(text) ? 'systemFunction' : 'function';
      else type = 'variable';
    }
    return { text, type };
  });
}
