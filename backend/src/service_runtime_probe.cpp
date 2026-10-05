#include "phantom/service.hpp"
#include "phantom/runtime_probe.hpp"

namespace phantom {

Json BackendService::handleRuntimeProbe(const Json& request) {
  const auto requestId = request.at("requestId").get<std::string>();
  std::stop_token cancellation;
  {
    std::lock_guard controlLock(controlMutex_);
    if (active_ && active_->id == requestId) {
      cancellation = active_->stop.get_token();
      active_->ready = true;
    }
  }
  controlWake_.notify_all();
  RuntimeProbeOptions options;
  options.gdbPath = options_.gdbPath;
  options.fixturePath = options_.runtimeProbeFixture;
  auto probe = probeRuntime(options, cancellation);
  {
    std::lock_guard controlLock(controlMutex_);
    if (active_ && active_->id == requestId) {
      active_->ready = false;
      // A cancel after the last subprocess exited still belongs to this
      // request until the control handoff is sealed. Preserve stage evidence,
      // but never advertise a cancelled request as available.
      if (active_->interruption == "cancel" || cancellation.stop_requested()) {
        probe["cancelled"] = true;
        probe["available"] = false;
        probe["reason"] = "cancelled";
      }
    }
  }
  // This operation owns a separate fixture and must not clear or interrupt
  // the live engine's control state through activeInterruption().
  return okResponse(request, {{"kind", "runtimeProbe"}, {"probe", std::move(probe)}});
}

}  // namespace phantom
