#!/bin/zsh
cd "${0:A:h}"
unset ELECTRON_RUN_AS_NODE
if [[ -d release/phantom-darwin-arm64/phantom.app ]]; then
  open release/phantom-darwin-arm64/phantom.app --args --workspace "$PWD"
else
  if [[ ! -d node_modules ]]; then
    npm install || exit 1
  fi
  npm run build && npm start
fi
