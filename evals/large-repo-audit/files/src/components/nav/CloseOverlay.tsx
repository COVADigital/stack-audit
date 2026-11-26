'use client'

export function CloseOverlay({ onClose }: { onClose: () => void }) {
  return (
    <div className="overlay-close" onClick={onClose}>
      Close
    </div>
  )
}
