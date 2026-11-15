'use client'

export function CartButton({ onOpen }: { onOpen: () => void }) {
  return (
    <button type="button" onClick={onOpen}>
      Cart
    </button>
  )
}
