type Review = { id: string; body: string }

export function ReviewBody({ review }: { review: Review }) {
  return <div className="review-body" dangerouslySetInnerHTML={{ __html: review.body }} />
}
