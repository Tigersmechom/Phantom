#include "phantom/service.hpp"
#include "phantom/recorder_probe.hpp"

namespace phantom {

Json BackendService::handleRecorderProbe(const Json& request) {
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

  RecorderProbeOptions probeOptions;
  // Host configuration only. The protocol accepts no paths or tool arguments.
  probeOptions.gdbPath = options_.gdbPath;
  probeOptions.fixturePath = options_.recorderProbeFixture;
  auto probe = probeRecorders(probeOptions, cancellation);

  {
    std::lock_guard controlLock(controlMutex_);
    if (active_ && active_->id == requestId) {
      // Close the reader/worker handoff under the same mutex used to apply
      // cancellation. A cancel which arrived after the last subprocess exited
      // but before this seal still belongs to this request. Completed stage
      // evidence stays valid; cancelled records the request-level outcome.
      active_->ready = false;
      if (active_->interruption == "cancel" || cancellation.stop_requested())
        probe["cancelled"] = true;
    }
  }
  // Do not call activeInterruption(): that execution helper clears the live
  // engine's interrupt flag. This isolated probe must never touch that engine.
  return okResponse(request, {{"kind", "recorderProbe"}, {"probe", std::move(probe)}});
}

}  // namespace phantom
