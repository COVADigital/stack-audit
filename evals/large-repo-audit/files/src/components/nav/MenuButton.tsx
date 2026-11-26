'use client'

export function MenuButton({ onOpen }: { onOpen: () => void }) {
  return (
    <button type="button" onClick={onOpen}>
      Menu
    </button>
  )
}
