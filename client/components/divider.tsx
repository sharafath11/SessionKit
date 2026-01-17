interface DividerProps {
  text?: string
}

export function Divider({ text }: DividerProps) {
  if (!text) {
    return <div className="my-6 border-t border-border" />
  }

  return (
    <div className="relative my-6">
      <div className="absolute inset-0 flex items-center">
        <div className="w-full border-t border-border" />
      </div>
      <div className="relative flex justify-center text-xs uppercase">
        <span className="bg-card px-2 text-muted-foreground">{text}</span>
      </div>
    </div>
  )
}
