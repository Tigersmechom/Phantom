#include "phantom/service.hpp"

#include <charconv>
#include <stdexcept>

namespace phantom {
std::vector<Json> BackendService::handleRecordedExecution(const Json& request,
                                                        const FrameSink& publish) {
  std::vector<Json> frames;
  const auto requestId = request.at("requestId").get<std::string>();
  const auto accepted = okResponse(request, {{"kind", "accepted"}});
  if (publish) publish(accepted); else frames.push_back(accepted);
  try {
    const auto& command = request.at("command");
    const auto kind = command.at("kind").get<std::string>();
    std::uint64_t instruction = 0;
    if (kind == "seekRecording") {
      const auto text = command.at("instruction").get<std::string>();
      const auto parsed = std::from_chars(text.data(), text.data() + text.size(), instruction);
      if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size())
        throw std::logic_error("validated recording cursor is not a uint64 decimal");
    }
    {
      std::lock_guard lock(controlMutex_);
      if (active_ && active_->id == requestId) active_->ready = true;
    }
    controlWake_.notify_all();
    GdbStop stop;
    GdbError error;
    const bool ok = kind == "seekRecording" ? engine_->seekRecording(instruction, stop, error) :
                                             engine_->reverseInstruction(stop, error);
    // Seal the control handoff before taking ownership of this checkpoint.
    // A late Stop targets the new checkpoint in the normal worker queue.
    const auto interruption = activeInterruption(requestId);
    if (interruption == "stop" && !stop.exited) {
      stop = engine_->stopAndSnapshot();
      stop.exited = true;
      stop.processInstanceId = processInstanceId_;
    }
    if (stop.exited) engine_->stop();
    if (stop.exited || (stop.stopped && engine_->live())) {
      const bool waiting = error.code == "INPUT_WAIT" || stop.reason == "input-wait";
      const auto reason = stop.exited ? "exit" : waiting ? "input-wait" :
          interruption == "pause" ? "pause" : error.code == "STEP_TIMEOUT" ? "step-timeout" :
          !ok ? "recording-error" : stop.reason == "breakpoint-hit" ? "breakpoint" :
          stop.reason.find("signal") != std::string::npos ? "signal" :
          kind == "seekRecording" ? "recording-seek" : "reverse-step";
      auto observation = makeObservation(stop, reason);
      auto state = makeState(observation, stop.exited ? "terminated" : waiting ? "waitingForInput" : "stopped",
                             stop.exitCode, stop.signalName.empty() ? std::nullopt :
                             std::optional<std::string>(stop.signalName));
      appendHistory(observation, state);
      frames.push_back(event({{"kind", "observation"}, {"observation", observation}}, processInstanceId_, requestId));
      frames.push_back(event({{"kind", "state"}, {"state", state}}, processInstanceId_, requestId));
    } else {
      // Unsupported native reverse and invalid retained cursors leave the
      // prior stop untouched. A dead adapter, however, must invalidate live.
      publishFailedState(frames, request);
    }
    const auto outcome = interruption == "cancel" ? "cancelled" :
        interruption == "pause" || interruption == "stop" ? "completed" :
        error.code == "INPUT_WAIT" ? "waiting" : error.code == "CANCELLED" ? "cancelled" :
        ok ? "completed" : "failed";
    std::optional<Json> failure;
    if (!ok && interruption.empty())
      failure = {{"code", error.code.empty() ? "READ_FAILED" : error.code},
                 {"message", error.message}, {"retryable", error.retryable}};
    emitCommandFinished(frames, request, outcome, failure);
  } catch (const std::exception& error) {
    engine_->stop();
    (void)activeInterruption(requestId);
    publishFailedState(frames, request);
    emitCommandFinished(frames, request, "failed",
                        Json{{"code", "INTERNAL"}, {"message", error.what()}, {"retryable", true}});
  }
  return frames;
}
}  // namespace phantom
