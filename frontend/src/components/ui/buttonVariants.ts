import { cva, type VariantProps } from "class-variance-authority";

export const buttonVariants = cva(
  "inline-flex items-center justify-center rounded-lg text-sm font-medium transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-1 disabled:pointer-events-none disabled:opacity-50 active:scale-[0.98]",
  {
    variants: {
      variant: {
        default: "bg-indigo-600 text-white shadow-xs hover:bg-indigo-700 hover:shadow-sm",
        secondary: "bg-slate-100 text-slate-800 border border-slate-200/80 hover:bg-slate-200/70 shadow-xs",
        outline: "border border-slate-200 bg-white text-slate-700 shadow-xs hover:bg-slate-50 hover:text-slate-900 hover:border-slate-300",
        ghost: "text-slate-600 hover:bg-slate-100/80 hover:text-slate-900",
        destructive: "bg-rose-600 text-white shadow-xs hover:bg-rose-700",
      },
      size: {
        default: "h-9 px-3.5 py-2",
        sm: "h-8 rounded-md px-2.5 text-xs",
        lg: "h-10 rounded-lg px-5 text-sm font-semibold",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

export type ButtonVariantProps = VariantProps<typeof buttonVariants>;

