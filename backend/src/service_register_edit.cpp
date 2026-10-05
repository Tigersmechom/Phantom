#include "phantom/service.hpp"
#include "phantom/register_edit.hpp"

namespace phantom {
std::vector<Json> BackendService::handleRegisterIntervention(const Json& request) {
  if (!liveObservation_.is_object() || liveState_.value("phase","") != "stopped")
    return {errorResponse(request,"STALE_CONTEXT","register edits require a stopped native session outside an input wait")};
  if (const auto failure = interventionBudgetError(request,interventionReservation)) return {*failure};
  const auto& command = request.at("command");
  const auto name = command.at("register").get<std::string>();
  Json target; GdbError error;
  if (!engine_->prepareRegisterWrite(name,target,error)) return engineError(request,error);
  Json audit = beginIntervention(request);
  audit["target"] = target;
  const auto reader = [&](std::string_view reg) -> RegisterEditRead {
    Json result; GdbError readError;
    if (!engine_->readRegisterValue(reg,result,readError))
      return {std::nullopt,engine_->live(),readError.code,readError.message};
    const auto value = result.at("valueHex").get<std::string>();
    result.erase("valueHex");
    if (result != target)
      return {std::nullopt,engine_->live(),"STALE_CONTEXT","register target metadata changed before read"};
    return {value,engine_->live(),{}, {}};
  };
  const auto writer = [&](std::string_view reg, std::string_view value) -> RegisterEditWrite {
    Json fresh; GdbError writeError;
    if (!engine_->prepareRegisterWrite(reg,fresh,writeError))
      return {false,false,engine_->live(),writeError.code,writeError.message};
    if (fresh != target)
      return {false,false,engine_->live(),"STALE_CONTEXT","register target metadata changed before write"};
    bool attempted = false;
    const bool acknowledged = engine_->writeRegisterValue(reg,value,attempted,writeError);
    return {attempted,acknowledged,engine_->live(),writeError.code,writeError.message};
  };
  audit["report"] = compareAndWriteRegister(name,command.at("expectedValueHex").get<std::string>(),
    command.at("replacementValueHex").get<std::string>(),reader,writer);
  return finishIntervention(request,std::move(audit),"registerIntervention",interventionReservation);
}
} // namespace phantom
