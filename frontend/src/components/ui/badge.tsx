import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "../../lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium tracking-tight transition-colors",
  {
    variants: {
      variant: {
        default: "bg-slate-900 text-white shadow-xs",
        secondary: "bg-slate-100 text-slate-700 border border-slate-200/70",
        success: "bg-emerald-50 text-emerald-700 border border-emerald-200/80 font-semibold",
        warning: "bg-amber-50 text-amber-700 border border-amber-200/80 font-semibold",
        destructive: "bg-rose-50 text-rose-700 border border-rose-200/80 font-semibold",
        outline: "border border-slate-300 text-slate-700 bg-white",
        info: "bg-sky-50 text-sky-700 border border-sky-200/80 font-medium",
        accent: "bg-indigo-50 text-indigo-700 border border-indigo-200/80 font-medium",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export function Badge({
  className,
  variant,
  ...props
}: React.HTMLAttributes<HTMLDivElement> & VariantProps<typeof badgeVariants>) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

