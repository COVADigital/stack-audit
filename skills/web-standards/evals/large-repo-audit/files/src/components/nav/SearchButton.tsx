'use client'

export function SearchButton({ onOpen }: { onOpen: () => void }) {
  return (
    <button type="button" onClick={onOpen}>
      Search
    </button>
  )
}
