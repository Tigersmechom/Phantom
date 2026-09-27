import { useState } from "react";
import { ChevronDown } from "lucide-react";
import AnimatedValue, { useChangeMotion } from "./AnimatedValue";

type DisplayValue = number | string | null;
export interface InspectorScalar {
  id: string;
  name: string;
  type: string;
  value: DisplayValue;
  kind: "local" | "argument";
  caption: string;
  unit?: string;
}
export interface InspectorArray {
  id: string;
  name: string;
  type: string;
  values: DisplayValue[];
  collapsible?: boolean;
  readingIndex?: number;
  changedIndex?: number;
  unvisitedFrom?: number;
  presentation?: "prefix";
  note?: { text: string; total: DisplayValue };
}
/** A projection of one active frame only. Caller data never enters this component. */
export interface InspectorFrame {
  id: string;
  functionName: string;
  scalars: InspectorScalar[];
  arrays: InspectorArray[];
}

export default function InspectorScope({
  frame,
  fileName,
  line,
}: {
  frame: InspectorFrame;
  fileName: string;
  line: number;
}) {
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const scopeMotion = useChangeMotion<HTMLDivElement>(frame.id, "scope");
  const onlyArguments =
    frame.scalars.length > 0 &&
    frame.scalars.every((variable) => variable.kind === "argument") &&
    frame.arrays.length === 0;
  return (
    <div
      data-testid="inspector-scope"
      data-frame-id={frame.id}
      data-function={frame.functionName}
    >
      {/* Changing activation removes its entire variable subtree synchronously. */}
      <div key={frame.id}>
        <div className="scope-label">
          <ChevronDown size={12} />
          <span>{onlyArguments ? "Аргументы" : "Локальная область"}</span>
          <span className="scope-line" />
          <span>
            {String(frame.scalars.length + frame.arrays.length).padStart(
              2,
              "0",
            )}
          </span>
        </div>
        {frame.scalars.length > 0 && (
          <div className="scalar-grid">
            {frame.scalars.map((variable) => (
              <div
                className="scalar-card"
                key={variable.id}
                data-value-cell
                data-variable={variable.name}
                data-variable-kind={variable.kind}
              >
                <div>
                  <span className="variable-name">{variable.name}</span>
                  <span className="type-label">{variable.type}</span>
                </div>
                <strong>
                  <AnimatedValue value={variable.value} />
                  {variable.unit && (
                    <span className="value-unit">{variable.unit}</span>
                  )}
                </strong>
                <small>{variable.caption}</small>
              </div>
            ))}
          </div>
        )}
        {frame.arrays.map((array) => {
          const expanded = !collapsed[array.id];
          const heading = (
            <>
              <ChevronDown size={12} className={expanded ? "" : "collapsed"} />
              <span className="variable-name">{array.name}</span>
              <span className="type-label">{array.type}</span>
              <span className="array-count">{array.values.length}</span>
            </>
          );
          return (
            <div
              className={`array-section ${array.presentation === "prefix" ? "prefix-section" : ""}`}
              key={array.id}
              data-variable={array.name}
            >
              {array.collapsible ? (
                <button
                  className="array-heading"
                  aria-expanded={expanded}
                  onClick={() =>
                    setCollapsed((previous) => ({
                      ...previous,
                      [array.id]: !previous[array.id],
                    }))
                  }
                >
                  {heading}
                </button>
              ) : (
                <div className="array-heading">{heading}</div>
              )}
              {expanded && (
                <div
                  className={`array-cells ${array.presentation === "prefix" ? "prefix-cells" : ""}`}
                >
                  {array.values.map((value, index) => (
                    <div
                      className={`array-cell ${index === array.readingIndex ? "reading" : ""} ${index === array.changedIndex ? "changed" : ""} ${array.unvisitedFrom !== undefined && index >= array.unvisitedFrom ? "unvisited" : ""}`}
                      key={index}
                      data-value-cell
                    >
                      <span>{index}</span>
                      <strong>
                        <AnimatedValue value={value} />
                      </strong>
                      {index === array.readingIndex && <i />}
                    </div>
                  ))}
                </div>
              )}
              {array.note && (
                <div className="array-note">
                  <span className="legend-dot" /> {array.note.text}
                  <span>
                    Σ <AnimatedValue value={array.note.total} />
                  </span>
                </div>
              )}
            </div>
          );
        })}
      </div>
      <div className="stack-row" ref={scopeMotion}>
        <span className="stack-symbol">↳</span>
        <span>{frame.functionName}</span>
        <span>
          {fileName}:{line}
        </span>
        <span className="stack-badge">#0</span>
      </div>
    </div>
  );
}
