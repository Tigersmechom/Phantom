#include "phantom/validation.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <set>
#include <sstream>
#include <unordered_set>
#include <vector>

namespace phantom {
namespace {

[[noreturn]] void bad(std::string code, std::string path, std::string message) {
  throw ValidationError(std::move(code), std::move(path), std::move(message));
}
[[noreturn]] void invalid(std::string path, std::string message) { bad("INVALID_REQUEST", std::move(path), std::move(message)); }
[[noreturn]] void limit(std::string path, std::string message) { bad("LIMIT_EXCEEDED", std::move(path), std::move(message)); }
[[noreturn]] void unsupported(std::string path, std::string message) { bad("UNSUPPORTED", std::move(path), std::move(message)); }

void expect_object(const Json& j, std::string_view p) { if (!j.is_object()) invalid(std::string(p), "expected object"); }
void expect_array(const Json& j, std::string_view p) { if (!j.is_array()) invalid(std::string(p), "expected array"); }
void exact_keys(const Json& j, std::initializer_list<std::string_view> keys, std::string_view p) {
  expect_object(j, p);
  std::set<std::string> allowed; for (auto k : keys) allowed.emplace(k);
  for (auto it = j.begin(); it != j.end(); ++it) if (!allowed.count(it.key())) invalid(std::string(p) + "." + it.key(), "unknown field");
  for (auto k : keys) (void)k;
}
bool has(const Json& j, std::string_view k) { return j.is_object() && j.contains(k); }
const Json& req(const Json& j, std::string_view k, std::string_view p) {
  if (!has(j, k)) invalid(std::string(p), "missing field '" + std::string(k) + "'");
  return j.at(std::string(k));
}
void string_value(const Json& j, std::string_view p, std::size_t max, bool nonempty = true) {
  if (!j.is_string()) invalid(std::string(p), "expected string");
  const auto& s = j.get_ref<const std::string&>();
  if (nonempty && s.empty()) invalid(std::string(p), "must not be empty");
  if (s.size() > max) limit(std::string(p), "string exceeds configured limit");
  try { validate_utf8(s); } catch (const ValidationError&) { throw; }
}
void id(const Json& j, std::string_view p, const ValidationLimits& l) { string_value(j, p, l.maxIdBytes); }
void safe_uint(const Json& j, std::string_view p, std::uint64_t max = max_json_safe_integer) {
  if (j.is_number_unsigned()) { if (j.get<std::uint64_t>() > max) invalid(std::string(p), "integer exceeds safe JSON range"); return; }
  if (!j.is_number_integer() || j.get<std::int64_t>() < 0 || static_cast<std::uint64_t>(j.get<std::int64_t>()) > max) invalid(std::string(p), "expected safe unsigned integer");
}
void positive_uint(const Json& j, std::string_view p, std::uint64_t max = max_json_safe_integer) {
  safe_uint(j, p, max); if (j.get<std::uint64_t>() == 0) invalid(std::string(p), "must be positive");
}
void boolean(const Json& j, std::string_view p) { if (!j.is_boolean()) invalid(std::string(p), "expected boolean"); }
void enum_string(const Json& j, std::string_view p, std::initializer_list<std::string_view> values) {
  string_value(j, p, 256); const auto s = j.get<std::string>();
  if (std::find(values.begin(), values.end(), s) == values.end()) invalid(std::string(p), "unknown enum value");
}
void array_limit(const Json& j, std::string_view p, std::size_t n) { expect_array(j,p); if (j.size() > n) limit(std::string(p), "array exceeds configured limit"); }

std::uint32_t hex4(std::string_view s) {
  std::uint32_t n = 0;
  for (char c : s) { n <<= 4; if (c >= '0' && c <= '9') n += c-'0'; else if (c >= 'a' && c <= 'f') n += c-'a'+10; else if (c >= 'A' && c <= 'F') n += c-'A'+10; else invalid("wire", "invalid unicode escape"); }
  return n;
}
void append_utf8(std::string& out, std::uint32_t cp) {
  if (cp <= 0x7f) out.push_back(static_cast<char>(cp));
  else if (cp <= 0x7ff) { out.push_back(char(0xc0 | (cp>>6))); out.push_back(char(0x80 | (cp&63))); }
  else if (cp <= 0xffff) { out.push_back(char(0xe0 | (cp>>12))); out.push_back(char(0x80 | ((cp>>6)&63))); out.push_back(char(0x80 | (cp&63))); }
  else { out.push_back(char(0xf0 | (cp>>18))); out.push_back(char(0x80 | ((cp>>12)&63))); out.push_back(char(0x80 | ((cp>>6)&63))); out.push_back(char(0x80 | (cp&63))); }
}

class WireScanner {
 public:
  WireScanner(std::string_view s, const ValidationLimits& l) : s_(s), l_(l) {}
  void run() { if (s_.size() > l_.maxWireBytes) limit("wire", "frame exceeds maximum size"); ws(); value(0); ws(); if (i_ != s_.size()) invalid("wire", "trailing data"); }
 private:
  std::string_view s_; const ValidationLimits& l_; std::size_t i_ = 0, nodes_ = 0;
  void node(std::size_t depth) { if (++nodes_ > l_.maxNodes) limit("wire", "JSON node budget exceeded"); if (depth > l_.maxDepth) limit("wire", "JSON depth exceeded"); }
  void ws() { while (i_ < s_.size() && (s_[i_] == ' ' || s_[i_] == '\t' || s_[i_] == '\n' || s_[i_] == '\r')) ++i_; }
  void expect(char c) { if (i_ >= s_.size() || s_[i_++] != c) invalid("wire", "malformed JSON"); }
  std::string str() {
    expect('"'); std::string out;
    while (i_ < s_.size()) {
      const unsigned char c = static_cast<unsigned char>(s_[i_++]);
      if (c == '"') { if (out.size() > l_.maxStringBytes) limit("wire", "string exceeds limit"); return out; }
      if (c < 0x20) invalid("wire", "control character in string");
      if (c != '\\') { std::size_t start = i_ - 1; while (i_ < s_.size() && static_cast<unsigned char>(s_[i_]) >= 0x20 && s_[i_] != '"' && s_[i_] != '\\') ++i_; auto part = s_.substr(start, i_ - start); validate_utf8(part); out.append(part); continue; }
      if (i_ >= s_.size()) invalid("wire", "unterminated escape");
      char e = s_[i_++];
      switch (e) {
        case '"': out += '"'; break; case '\\': out += '\\'; break; case '/': out += '/'; break;
        case 'b': out += '\b'; break; case 'f': out += '\f'; break; case 'n': out += '\n'; break; case 'r': out += '\r'; break; case 't': out += '\t'; break;
        case 'u': {
          if (i_ + 4 > s_.size()) invalid("wire", "short unicode escape"); std::uint32_t cp = hex4(s_.substr(i_,4)); i_ += 4;
          if (cp >= 0xd800 && cp <= 0xdbff) { if (i_ + 6 > s_.size() || s_[i_] != '\\' || s_[i_+1] != 'u') invalid("wire", "unpaired high surrogate"); i_ += 2; auto low = hex4(s_.substr(i_,4)); i_ += 4; if (low < 0xdc00 || low > 0xdfff) invalid("wire", "invalid surrogate pair"); cp = 0x10000 + ((cp - 0xd800)<<10) + (low - 0xdc00); }
          else if (cp >= 0xdc00) invalid("wire", "unpaired low surrogate"); append_utf8(out, cp); break;
        }
        default: invalid("wire", "invalid escape");
      }
      if (out.size() > l_.maxStringBytes) limit("wire", "string exceeds limit");
    }
    invalid("wire", "unterminated string");
  }
  void number() {
    const std::size_t start = i_; if (s_[i_] == '-') ++i_; if (i_ >= s_.size()) invalid("wire", "bad number");
    if (s_[i_] == '0') ++i_; else { if (s_[i_] < '1' || s_[i_] > '9') invalid("wire", "bad number"); while (i_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[i_]))) ++i_; }
    bool decimal = false; if (i_ < s_.size() && s_[i_] == '.') { decimal = true; ++i_; std::size_t n=i_; while (i_<s_.size() && std::isdigit(static_cast<unsigned char>(s_[i_]))) ++i_; if (i_==n) invalid("wire", "bad number"); }
    if (i_ < s_.size() && (s_[i_] == 'e' || s_[i_] == 'E')) { decimal = true; ++i_; if (i_<s_.size() && (s_[i_]=='+' || s_[i_]=='-')) ++i_; std::size_t n=i_; while (i_<s_.size() && std::isdigit(static_cast<unsigned char>(s_[i_]))) ++i_; if(i_==n) invalid("wire", "bad exponent"); }
    const auto n = s_.substr(start, i_-start);
    if (!decimal) {
      std::string digits(n); if (!digits.empty() && digits[0]=='-') digits.erase(0,1); while (digits.size()>1 && digits[0]=='0') digits.erase(0,1);
      if (digits.size() > 16 || (digits.size()==16 && digits > "9007199254740991")) invalid("wire", "integer exceeds safe JSON range");
    } else {
      char* end = nullptr; std::string z(n); long double x = std::strtold(z.c_str(), &end); if (!std::isfinite(x) || std::abs(x) > static_cast<long double>(max_json_safe_integer)) invalid("wire", "number exceeds safe JSON range");
    }
  }
  void value(std::size_t depth) {
    node(depth); ws(); if (i_ >= s_.size()) invalid("wire", "missing value");
    switch (s_[i_]) {
      case '{': object(depth); break; case '[': array(depth); break; case '"': (void)str(); break; case 't': if (s_.substr(i_,4)!="true") invalid("wire","bad literal"); i_+=4; break; case 'f': if(s_.substr(i_,5)!="false") invalid("wire","bad literal"); i_+=5; break; case 'n': if(s_.substr(i_,4)!="null") invalid("wire","bad literal"); i_+=4; break; default: if (s_[i_]=='-' || std::isdigit(static_cast<unsigned char>(s_[i_]))) number(); else invalid("wire","bad value");
    }
  }
  void object(std::size_t depth) { expect('{'); ws(); std::unordered_set<std::string> keys; if(i_<s_.size() && s_[i_]=='}'){++i_;return;} for(;;){ if(keys.size()>=l_.maxObjectMembers) limit("wire","object member budget exceeded"); if(i_>=s_.size()||s_[i_]!='"') invalid("wire","object key must be string"); auto k=str(); if(!keys.insert(k).second) invalid("wire","duplicate object key"); ws(); expect(':'); value(depth+1); ws(); if(i_>=s_.size()) invalid("wire","unterminated object"); if(s_[i_]=='}'){++i_;return;} expect(','); ws(); }}
  void array(std::size_t depth) { expect('['); ws(); std::size_t n=0; if(i_<s_.size()&&s_[i_]==']'){++i_;return;} for(;;){if(++n>l_.maxArrayElements)limit("wire","array element budget exceeded"); value(depth+1);ws();if(i_>=s_.size())invalid("wire","unterminated array");if(s_[i_]==']'){++i_;return;}expect(',');ws();}}
};

void check_tree(const Json& j, const ValidationLimits& l, std::size_t depth=0, std::size_t* nodes=nullptr) {
  std::size_t local=0; if(!nodes)nodes=&local; if(++*nodes>l.maxNodes)limit("json","node budget exceeded"); if(depth>l.maxDepth)limit("json","depth exceeded");
  if(j.is_string()){string_value(j,"json",l.maxStringBytes,false);return;} if(j.is_object()){if(j.size()>l.maxObjectMembers)limit("json","object member budget exceeded");for(auto&x:j.items())check_tree(x.value(),l,depth+1,nodes);} else if(j.is_array()){if(j.size()>l.maxArrayElements)limit("json","array budget exceeded");for(auto&x:j)check_tree(x,l,depth+1,nodes);} else if(j.is_number_float() && (!std::isfinite(j.get<double>()) || std::abs(j.get<double>())>max_json_safe_integer))invalid("json","unsafe number"); else if(j.is_number_unsigned() && j.get<std::uint64_t>() > max_json_safe_integer) invalid("json","unsafe number"); else if(j.is_number_integer()) { const auto value = j.get<std::int64_t>(); if (value < -static_cast<std::int64_t>(max_json_safe_integer) || value > static_cast<std::int64_t>(max_json_safe_integer)) invalid("json","unsafe number"); }
}

void validate_range_bounds(const Json& range, std::string_view p, std::size_t utf16Length) {
  exact_keys(range,{"start","end"},p);
  const auto& start = req(range, "start", p);
  const auto& end = req(range, "end", p);
  safe_uint(start, std::string(p)+".start", utf16Length);
  safe_uint(end, std::string(p)+".end", utf16Length);
  if (start.get<std::size_t>() > end.get<std::size_t>()) invalid(std::string(p),"range start after end");
}
void document(const Json& d, const ValidationLimits& l) { exact_keys(d,{"documentId","revisionId","path","text","sha256"},"document"); id(req(d,"documentId","document"),"document.documentId",l); id(req(d,"revisionId","document"),"document.revisionId",l); string_value(req(d,"path","document"),"document.path",l.maxStringBytes); const auto&t=req(d,"text","document");string_value(t,"document.text",l.maxSourceBytes,false); const auto& hash=req(d,"sha256","document"); string_value(hash,"document.sha256",128); if(hash.get<std::string>().size()!=64 || hash.get<std::string>().find_first_not_of("0123456789abcdefABCDEF")!=std::string::npos) invalid("document.sha256","must be a SHA-256 hexadecimal digest"); }
void span(const Json& s, const ValidationLimits& l) { if(s.is_null())return; exact_keys(s,{"documentId","revisionId","range","start","end"},"span");id(req(s,"documentId","span"),"span.documentId",l);id(req(s,"revisionId","span"),"span.revisionId",l);validate_range_bounds(req(s,"range","span"),"span.range",l.maxSourceBytes); for(auto k:{"start","end"}){const auto&x=req(s,k,"span");std::string p=std::string("span.")+k;exact_keys(x,{"line","column"},p);positive_uint(req(x,"line",p),p);positive_uint(req(x,"column",p),p);}}
void workspace(const Json& w,const ValidationLimits& l){exact_keys(w,{"id","revisionId"},"workspace");id(req(w,"id","workspace"),"workspace.id",l);id(req(w,"revisionId","workspace"),"workspace.revisionId",l);}
void session(const Json& s,const ValidationLimits& l){if(s.is_null())return;exact_keys(s,{"id","generation"},"session");id(req(s,"id","session"),"session.id",l);safe_uint(req(s,"generation","session"),"session.generation");}
void stop(const Json& s,const ValidationLimits& l){exact_keys(s,{"stopId","stateRevision"},"stop");id(req(s,"stopId","stop"),"stop.stopId",l);safe_uint(req(s,"stateRevision","stop"),"stop.stateRevision");}
void source_bundle(const Json& s,const ValidationLimits& l){exact_keys(s,{"id","documents"},"source");id(req(s,"id","source"),"source.id",l);array_limit(req(s,"documents","source"),"source.documents",l.maxDocuments);std::unordered_set<std::string> ids;std::size_t total=0;for(const auto&d:req(s,"documents","source")){document(d,l);if(!ids.insert(d["documentId"].get<std::string>()).second)invalid("source.documents","duplicate documentId");total+=d["text"].get_ref<const std::string&>().size();if(total>l.maxSourceBytes)limit("source.documents","source bundle exceeds byte budget");}}
void config(const Json& c,const ValidationLimits& l){exact_keys(c,{"revisionId","compiler","flags","outputDirectory"},"configuration");id(req(c,"revisionId","configuration"),"configuration.revisionId",l);string_value(req(c,"compiler","configuration"),"configuration.compiler",l.maxStringBytes);array_limit(req(c,"flags","configuration"),"configuration.flags",l.maxArguments);for(const auto&x:req(c,"flags","configuration"))string_value(x,"configuration.flags",l.maxArgumentBytes,false);string_value(req(c,"outputDirectory","configuration"),"configuration.outputDirectory",l.maxStringBytes);}
void submitted(const Json&s,const ValidationLimits&l){exact_keys(s,{"id","text","encoding","closeAfterWrite"},"input");id(req(s,"id","input"),"input.id",l);string_value(req(s,"text","input"),"input.text",l.maxInputBytes,false);enum_string(req(s,"encoding","input"),"input.encoding",{"utf-8"});if(!req(s,"closeAfterWrite","input").is_boolean()||!req(s,"closeAfterWrite","input").get<bool>())invalid("input.closeAfterWrite","v1 requires true");}
bool environment_name(std::string_view name) {
  if (name.empty() || !(std::isalpha(static_cast<unsigned char>(name.front())) || name.front() == '_')) return false;
  return std::all_of(name.begin() + 1, name.end(), [](unsigned char c) {
    return std::isalnum(c) || c == '_';
  });
}
bool mi_argument_safe(std::string_view value) {
  return value.find('\0') == std::string_view::npos && value.find('\n') == std::string_view::npos &&
         value.find('\r') == std::string_view::npos;
}
void breakpoint(const Json& b, const ValidationLimits& l) {
  exact_keys(b,{"id","range","enabled","condition","hitCount"},"breakpoint"); id(req(b,"id","breakpoint"),"breakpoint.id",l);
  const auto& range = req(b, "range", "breakpoint");
  if (range.is_null()) invalid("breakpoint.range","must be a source span"); span(range,l); boolean(req(b,"enabled","breakpoint"),"breakpoint.enabled");
  if (has(b,"condition")) string_value(b["condition"],"breakpoint.condition",l.maxStringBytes,false);
  if (has(b,"hitCount")) positive_uint(b["hitCount"],"breakpoint.hitCount");
}

} // namespace

ValidationError::ValidationError(std::string c,std::string p,std::string m):std::runtime_error(m),code(std::move(c)),path(std::move(p)){}

void validate_utf8(std::string_view s){for(std::size_t i=0;i<s.size();){unsigned char c=s[i];std::size_t n=1;std::uint32_t cp=0;if(c<0x80)cp=c;else if(c>=0xc2&&c<=0xdf){n=2;cp=c&31;}else if(c>=0xe0&&c<=0xef){n=3;cp=c&15;}else if(c>=0xf0&&c<=0xf4){n=4;cp=c&7;}else invalid("utf8","invalid UTF-8");if(i+n>s.size())invalid("utf8","truncated UTF-8");for(std::size_t j=1;j<n;j++){unsigned char d=s[i+j];if((d&0xc0)!=0x80)invalid("utf8","invalid UTF-8 continuation");cp=(cp<<6)|(d&63);}if((n==2&&cp<0x80)||(n==3&&cp<0x800)||(n==4&&cp<0x10000)||(cp>=0xd800&&cp<=0xdfff)||cp>0x10ffff)invalid("utf8","noncanonical UTF-8");i+=n;}}
TextPosition utf8_byte_position(std::string_view s,std::size_t b){validate_utf8(s);if(b>s.size())invalid("offset","byte offset outside text");TextPosition p;for(std::size_t i=0;i<b;){unsigned char c=s[i];std::size_t n=c<0x80?1:c<0xe0?2:c<0xf0?3:4;std::uint32_t cp=c<0x80?c:c&((1u<<(8-n))-1);for(std::size_t j=1;j<n;j++)cp=(cp<<6)|(static_cast<unsigned char>(s[i+j])&63);if(cp>0xffff)p.utf16+=2;else p.utf16++;if(cp=='\n'){p.line++;p.column=1;}else p.column+=(cp>0xffff?2:1);i+=n;}if(b<s.size()&& (static_cast<unsigned char>(s[b])&0xc0)==0x80)invalid("offset","byte offset splits UTF-8 code point");return p;}
std::size_t utf16_to_utf8_offset(std::string_view s,std::size_t u){validate_utf8(s);std::size_t at=0,units=0;for(;at<s.size();){if(units==u)return at;unsigned char c=s[at];std::size_t n=c<0x80?1:c<0xe0?2:c<0xf0?3:4;std::uint32_t cp=c<0x80?c:c&((1u<<(8-n))-1);for(std::size_t j=1;j<n;j++)cp=(cp<<6)|(static_cast<unsigned char>(s[at+j])&63);std::size_t add=cp>0xffff?2:1;if(u<units+add)invalid("offset","UTF-16 offset splits surrogate pair");units+=add;at+=n;}if(units!=u)invalid("offset","UTF-16 offset outside text");return at;}

Json parse_wire_json(std::string_view wire,const ValidationLimits& l){WireScanner(wire,l).run();try{auto j=Json::parse(wire);check_tree(j,l);return j;}catch(const ValidationError&){throw;}catch(const std::exception&e){bad("INVALID_REQUEST","wire",e.what());}}

void validate_source_span(const Json& s,const Json& d,const ValidationLimits& l){if(s.is_null())return;document(d,l);span(s,l);if(s["documentId"]!=d["documentId"]||s["revisionId"]!=d["revisionId"])invalid("span","document/revision mismatch");const auto&text=d["text"].get_ref<const std::string&>();std::size_t len=0;for(std::size_t i=0;i<text.size();){unsigned char c=text[i];std::size_t n=c<0x80?1:c<0xe0?2:c<0xf0?3:4;std::uint32_t cp=c<0x80?c:c&((1u<<(8-n))-1);for(std::size_t k=1;k<n;k++)cp=(cp<<6)|(static_cast<unsigned char>(text[i+k])&63);len+=cp>0xffff?2:1;i+=n;}validate_range_bounds(s["range"],"span.range",len);for(auto k:{"start","end"}){auto off=utf16_to_utf8_offset(text,s["range"][k].get<std::size_t>());auto pos=utf8_byte_position(text,off);if(pos.line!=s[k]["line"]||pos.column!=s[k]["column"])invalid(std::string("span.")+k,"line/column disagree with UTF-16 range");}}
void validate_input_trace(const Json&t,const Json&sub,const ValidationLimits&l){
  if(t.is_null())return;
  exact_keys(t,{"revision","consumedRanges","activeRange","status"},"trace");
  submitted(sub,l);
  const auto& revision = req(t, "revision", "trace");
  const auto& consumed = req(t, "consumedRanges", "trace");
  const auto& status = req(t, "status", "trace");
  if(revision!=sub["text"])invalid("trace.revision","must equal exact submitted text");
  enum_string(status,"trace.status",{"idle","waiting","reading","complete","error"});
  const auto&text=sub["text"].get_ref<const std::string&>();std::size_t len=0;
  for(std::size_t i=0;i<text.size();){unsigned char c=text[i];std::size_t n=c<0x80?1:c<0xe0?2:c<0xf0?3:4;std::uint32_t cp=c<0x80?c:c&((1u<<(8-n))-1);for(std::size_t k=1;k<n;k++)cp=(cp<<6)|(static_cast<unsigned char>(text[i+k])&63);len+=cp>0xffff?2:1;i+=n;}
  auto check=[&](const Json&r,const std::string&p){validate_range_bounds(r,p,len);(void)utf16_to_utf8_offset(text,r.at("start").get<std::size_t>());(void)utf16_to_utf8_offset(text,r.at("end").get<std::size_t>());};
  array_limit(consumed,"trace.consumedRanges",l.maxArguments);for(const auto&r:consumed)check(r,"trace.range");if(has(t,"activeRange")&&!t["activeRange"].is_null())check(t["activeRange"],"trace.activeRange");
}

void validate_scalar_value(const Json&v,const ValidationLimits&l){
  expect_object(v,"value"); const auto& k=req(v,"kind","value"); string_value(k,"value.kind",64); const auto kind=k.get<std::string>();
  if(kind=="integer"){
    exact_keys(v,{"kind","decimal","bits","signed"},"value"); const auto& decimal=req(v,"decimal","value"); string_value(decimal,"value.decimal",l.maxStringBytes); const auto&dec=decimal.get_ref<const std::string&>(); std::size_t first=dec[0]=='-'?1:0; if(first==dec.size()||dec.find_first_not_of("0123456789",first)!=std::string::npos)invalid("value.decimal","must be decimal"); positive_uint(req(v,"bits","value"),"value.bits",l.maxScalarBits); boolean(req(v,"signed","value"),"value.signed");
  }else if(kind=="float"){
    exact_keys(v,{"kind","text","bits","classification","rawBitsHex"},"value"); string_value(req(v,"text","value"),"value.text",l.maxStringBytes,false); positive_uint(req(v,"bits","value"),"value.bits",l.maxScalarBits); enum_string(req(v,"classification","value"),"value.classification",{"finite","nan","positive-infinity","negative-infinity","negative-zero"}); if(has(v,"rawBitsHex"))string_value(v.at("rawBitsHex"),"value.rawBitsHex",l.maxStringBytes,false);
  }else if(kind=="boolean"){
    exact_keys(v,{"kind","value"},"value"); boolean(req(v,"value","value"),"value.value");
  }else if(kind=="pointer"){
    exact_keys(v,{"kind","addressHex","pointeeType"},"value"); string_value(req(v,"addressHex","value"),"value.addressHex",l.maxStringBytes); string_value(req(v,"pointeeType","value"),"value.pointeeType",l.maxStringBytes);
  }else if(kind=="string"){
    exact_keys(v,{"kind","text","encoding","byteLength","truncated"},"value"); string_value(req(v,"text","value"),"value.text",l.maxStringBytes,false); string_value(req(v,"encoding","value"),"value.encoding",256); safe_uint(req(v,"byteLength","value"),"value.byteLength"); boolean(req(v,"truncated","value"),"value.truncated");
  }else if(kind=="aggregate"){
    exact_keys(v,{"kind","summary","elementCount","childrenReference"},"value"); string_value(req(v,"summary","value"),"value.summary",l.maxStringBytes,false); if(has(v,"elementCount"))string_value(v.at("elementCount"),"value.elementCount",l.maxStringBytes); if(has(v,"childrenReference"))id(v.at("childrenReference"),"value.childrenReference",l);
  }else unsupported("value.kind","unknown scalar kind");
}
void validate_runtime_value(const Json&v,const ValidationLimits&l){expect_object(v,"runtime");const auto& availability=req(v,"availability","runtime");if(availability=="available"){exact_keys(v,{"availability","value"},"runtime");validate_scalar_value(req(v,"value","runtime"),l);}else if(availability=="unavailable"){exact_keys(v,{"availability","reason","detail"},"runtime");enum_string(req(v,"reason","runtime"),"runtime.reason",{"not-declared","uninitialized","not-captured","out-of-scope","optimized-out","read-error","truncated","unsupported"});if(has(v,"detail"))string_value(v.at("detail"),"runtime.detail",l.maxStringBytes,false);}else invalid("runtime.availability","unknown availability");}

void validate_expression_trace(const Json&t,const ValidationLimits&l){exact_keys(t,{"id","range","evidence","groups","activeStageIds","complete"},"expression");id(req(t,"id","expression"),"expression.id",l);const auto&tr=req(t,"range","expression");if(!tr.is_null())span(tr,l);enum_string(req(t,"evidence","expression"),"expression.evidence",{"debugger","instrumentation"});const auto&groups=req(t,"groups","expression");array_limit(groups,"expression.groups",l.maxArguments);std::unordered_set<std::string> ids;std::unordered_set<std::string> active;const auto&activeIds=req(t,"activeStageIds","expression");array_limit(activeIds,"expression.activeStageIds",l.maxArguments);for(const auto&x:activeIds){id(x,"expression.activeStageId",l);if(!active.insert(x.get<std::string>()).second)invalid("expression.activeStageIds","duplicate id");}boolean(req(t,"complete","expression"),"expression.complete");for(const auto&g:groups){exact_keys(g,{"id","relationToPrevious","stages"},"expression.group");id(req(g,"id","expression.group"),"expression.group.id",l);enum_string(req(g,"relationToPrevious","expression.group"),"expression.group.relationToPrevious",{"observed-after","not-established"});const auto&stages=req(g,"stages","expression.group");array_limit(stages,"expression.group.stages",l.maxArguments);for(const auto&st:stages){exact_keys(st,{"id","kind","operator","label","range","operands","result","targetLocator","dependsOn"},"expression.stage");id(req(st,"id","expression.stage"),"expression.stage.id",l);if(!ids.insert(st["id"].get<std::string>()).second)invalid("expression.stage.id","duplicate id");enum_string(req(st,"kind","expression.stage"),"expression.stage.kind",{"operator","call","return","store"});string_value(req(st,"operator","expression.stage"),"expression.stage.operator",256,false);string_value(req(st,"label","expression.stage"),"expression.stage.label",l.maxStringBytes,false);const auto&sr=req(st,"range","expression.stage");if(!sr.is_null())span(sr,l);const auto&ops=req(st,"operands","expression.stage");array_limit(ops,"expression.stage.operands",l.maxArguments);for(const auto&o:ops){exact_keys(o,{"name","value","range"},"expression.operand");if(has(o,"name"))string_value(o["name"],"expression.operand.name",l.maxStringBytes,false);validate_runtime_value(req(o,"value","expression.operand"),l);if(has(o,"range")&&!o["range"].is_null())span(o["range"],l);}validate_runtime_value(req(st,"result","expression.stage"),l);if(has(st,"targetLocator"))id(st["targetLocator"],"expression.stage.targetLocator",l);const auto&deps=req(st,"dependsOn","expression.stage");array_limit(deps,"expression.stage.dependsOn",l.maxArguments);for(const auto&d:deps){id(d,"expression.stage.dependsOn",l);}}}for(const auto&g:groups)for(const auto&st:g["stages"])for(const auto&d:st["dependsOn"])if(!ids.count(d.get<std::string>()))invalid("expression.stage.dependsOn","dangling dependency");
  for (const auto& a : active) if (!ids.count(a)) invalid("expression.activeStageIds", "unknown stage id");
  std::unordered_set<std::string> groupIds;
  for (const auto& g : t["groups"]) { const auto gid=g["id"].get<std::string>(); if (!groupIds.insert(gid).second || ids.count(gid)) invalid("expression.group.id", "duplicate id"); }
  std::unordered_map<std::string, std::vector<std::string>> edges;
  for (const auto& g : t["groups"]) for (const auto& st : g["stages"]) for (const auto& d : st["dependsOn"]) edges[st["id"].get<std::string>()].push_back(d.get<std::string>());
  std::unordered_set<std::string> visiting, visited;
  std::function<void(const std::string&)> visit = [&](const std::string& n) { if (visiting.count(n)) invalid("expression.stage.dependsOn", "dependency cycle"); if (visited.count(n)) return; visiting.insert(n); for (const auto& d : edges[n]) visit(d); visiting.erase(n); visited.insert(n); };
  for (const auto& x : ids) visit(x);
}

void validate_connect(const Json& c, const ValidationLimits& l) {
  // The adapter DTO is {supportedProtocolVersions}; stdio adds an optional
  // discriminant/workspace envelope so a stream can multiplex frame kinds.
  exact_keys(c,{"kind","supportedProtocolVersions","workspace"},"connect");
  if (c.contains("kind") && (!c.at("kind").is_string() || c.at("kind") != "connect")) invalid("connect.kind","expected connect");
  if (!c.contains("supportedProtocolVersions")) invalid("connect.supportedProtocolVersions","missing field");
  array_limit(c.at("supportedProtocolVersions"),"supportedProtocolVersions",16);
  if (c.at("supportedProtocolVersions").empty()) invalid("supportedProtocolVersions","must not be empty");
  for (const auto& v : c.at("supportedProtocolVersions")) safe_uint(v,"supportedProtocolVersions");
  if (c.contains("workspace")) workspace(c.at("workspace"),l);
}

void validate_request(const Json& r, const ValidationLimits& l) {
  exact_keys(r, {"protocolVersion","requestId","workspace","session","expectedStop","command"}, "request");
  const auto& protocol = req(r, "protocolVersion", "request");
  if (!protocol.is_number_integer() || protocol != 1) unsupported("protocolVersion", "only protocol version 1 is supported");
  id(req(r, "requestId", "request"), "requestId", l); workspace(req(r, "workspace", "request"), l); session(req(r, "session", "request"), l);
  if (has(r, "expectedStop")) stop(r["expectedStop"], l);
  const auto& c = req(r, "command", "request"); string_value(req(c, "kind", "command"), "command.kind", 64);
  const std::string kind = c.at("kind").get<std::string>();
  if ((kind == "step" || kind == "continue" || kind == "readVariables" || kind == "writeVariable" || kind == "readMemory") && !has(r, "expectedStop"))
    invalid("request.expectedStop", "required for this live-process command");
  auto only = [&](std::initializer_list<std::string_view> allowed) { std::set<std::string> a; for (auto k : allowed) a.emplace(k); for (auto it = c.begin(); it != c.end(); ++it) if (!a.count(it.key())) invalid("command." + it.key(), "field not allowed for this command"); };
  if (kind == "capabilities" || kind == "continue" || kind == "pause" || kind == "stop" || kind == "getState") { only({"kind"}); return; }
  if (kind == "build") { only({"kind","source","configuration","architecture"}); source_bundle(req(c,"source","command"),l); config(req(c,"configuration","command"),l); enum_string(req(c,"architecture","command"),"command.architecture",{"arm64","x86_64"}); return; }
  if (kind == "launch") {
    only({"kind","buildId","input","argv","environment","stopAtEntry"}); id(req(c,"buildId","command"),"command.buildId",l); submitted(req(c,"input","command"),l);
    const auto& argv=req(c,"argv","command"); array_limit(argv,"command.argv",l.maxArguments); for(const auto& x: argv) { string_value(x,"command.argv",l.maxArgumentBytes,false); if(!mi_argument_safe(x.get<std::string>())) invalid("command.argv","arguments must not contain NUL or line breaks"); }
    const auto& env=req(c,"environment","command"); expect_object(env,"command.environment"); if(env.size()>l.maxArguments) limit("command.environment","too many variables"); std::size_t total=0;
    for(auto it=env.begin();it!=env.end();++it){ string_value(Json(it.key()),"command.environment.key",l.maxArgumentBytes); if(!environment_name(it.key())) invalid("command.environment.key","must be a POSIX environment name"); string_value(it.value(),"command.environment",l.maxArgumentBytes,false); if(it.key().find('\0') != std::string::npos || it.value().get<std::string>().find('\0') != std::string::npos) invalid("command.environment","must not contain NUL"); total += it.key().size()+it.value().get<std::string>().size(); }
    if(total>l.maxEnvironmentBytes) limit("command.environment","environment exceeds limit"); boolean(req(c,"stopAtEntry","command"),"command.stopAtEntry"); return;
  }
  if (kind == "step") { only({"kind","stepKind"}); enum_string(req(c,"stepKind","command"),"command.stepKind",{"over","into","out","instruction"}); return; }
  if (kind == "listHistory") { only({"kind","branchId","afterOrdinal","limit"}); id(req(c,"branchId","command"),"command.branchId",l); const auto& a=req(c,"afterOrdinal","command"); if(!a.is_null()) safe_uint(a,"command.afterOrdinal"); positive_uint(req(c,"limit","command"),"command.limit",l.maxPageSize); return; }
  if (kind == "readHistory") { only({"kind","point"}); const auto& p=req(c,"point","command"); exact_keys(p,{"branchId","eventOrdinal"},"command.point"); id(req(p,"branchId","command.point"),"command.point.branchId",l); safe_uint(req(p,"eventOrdinal","command.point"),"command.point.eventOrdinal"); return; }
  if (kind == "restoreExecution") { only({"kind","point","strategy"}); unsupported("command.strategy","verified replay is capability-gated"); }
  if (kind == "setBreakpoints") { only({"kind","documentId","revisionId","breakpoints"}); id(req(c,"documentId","command"),"command.documentId",l); id(req(c,"revisionId","command"),"command.revisionId",l); const auto& bs=req(c,"breakpoints","command"); array_limit(bs,"command.breakpoints",l.maxBreakpoints); for(const auto& b:bs) breakpoint(b,l); return; }
  if (kind == "readVariables") { only({"kind","reference","start","count"}); id(req(c,"reference","command"),"command.reference",l); safe_uint(req(c,"start","command"),"command.start"); positive_uint(req(c,"count","command"),"command.count",l.maxPageSize); return; }
  if (kind == "writeVariable") { only({"kind","locator","expected","value"}); id(req(c,"locator","command"),"command.locator",l); validate_runtime_value(req(c,"expected","command"),l); validate_scalar_value(req(c,"value","command"),l); return; }
  if (kind == "disassemble") { only({"kind","buildId","target","maxInstructions"}); id(req(c,"buildId","command"),"command.buildId",l); const auto& t=req(c,"target","command"); expect_object(t,"command.target"); const auto tk=t.value("kind",""); if(tk=="pc"){exact_keys(t,{"kind","addressHex"},"command.target");string_value(req(t,"addressHex","command.target"),"command.target.addressHex",l.maxIdBytes);} else if(tk=="source"){exact_keys(t,{"kind","range"},"command.target");span(req(t,"range","command.target"),l);} else invalid("command.target.kind","unknown target"); positive_uint(req(c,"maxInstructions","command"),"command.maxInstructions",l.maxInstructions); return; }
  if (kind == "readMemory") { only({"kind","addressHex","byteCount"}); string_value(req(c,"addressHex","command"),"command.addressHex",l.maxIdBytes); positive_uint(req(c,"byteCount","command"),"command.byteCount",l.maxMemoryReadBytes); return; }
  if (kind == "cancel") { only({"kind","targetRequestId"}); id(req(c,"targetRequestId","command"),"command.targetRequestId",l); return; }
  if (kind == "replayEvents") { only({"kind","afterSequence"}); safe_uint(req(c,"afterSequence","command"),"command.afterSequence"); return; }
  unsupported("command.kind", "unknown command");
}

} // namespace phantom
