import AppKit
let size: CGFloat = 1024
let image = NSImage(size: NSSize(width: size, height: size))
image.lockFocus()
let shape = NSBezierPath(roundedRect: NSRect(x: 42, y: 42, width: 940, height: 940), xRadius: 210, yRadius: 210)
NSColor(calibratedRed: 0.055, green: 0.065, blue: 0.073, alpha: 1).setFill()
shape.fill()
NSGradient(starting: NSColor(calibratedRed: 0.17, green: 0.20, blue: 0.21, alpha: 1), ending: NSColor(calibratedRed: 0.025, green: 0.036, blue: 0.04, alpha: 1))?.draw(in: shape, angle: -60)
NSColor(calibratedRed: 0.82, green: 0.93, blue: 0.72, alpha: 1).setStroke()
let logo = NSBezierPath()
logo.lineWidth = 54
logo.lineCapStyle = .round
logo.lineJoinStyle = .round
logo.move(to: NSPoint(x: 330, y: 260))
logo.line(to: NSPoint(x: 330, y: 750))
logo.line(to: NSPoint(x: 570, y: 750))
logo.curve(to: NSPoint(x: 705, y: 625), controlPoint1: NSPoint(x: 655, y: 750), controlPoint2: NSPoint(x: 705, y: 705))
logo.curve(to: NSPoint(x: 570, y: 500), controlPoint1: NSPoint(x: 705, y: 545), controlPoint2: NSPoint(x: 655, y: 500))
logo.line(to: NSPoint(x: 330, y: 500))
logo.stroke()
image.unlockFocus()
let data=NSBitmapImageRep(data:image.tiffRepresentation!)!.representation(using:.png,properties:[:])!
try data.write(to:URL(fileURLWithPath:CommandLine.arguments[1]))
