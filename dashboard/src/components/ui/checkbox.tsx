"use client"

import * as React from "react"
import { Check } from "lucide-react"

import { cn } from "@/lib/utils"

interface CheckboxProps extends React.InputHTMLAttributes<HTMLInputElement> {
    checked?: boolean;
    onCheckedChange?: (checked: boolean) => void;
}

const Checkbox = React.forwardRef<HTMLInputElement, CheckboxProps>(
    ({ className, checked, onCheckedChange, ...props }, ref) => {
        return (
            <div className="relative flex items-center">
                <input
                    type="checkbox"
                    className="peer h-4 w-4 shrink-0 cursor-pointer appearance-none rounded-sm border border-primary shadow focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:bg-primary data-[state=checked]:text-primary-foreground"
                    ref={ref}
                    checked={checked}
                    onChange={(e) => onCheckedChange?.(e.target.checked)}
                    {...props}
                />
                <div className={cn(
                    "pointer-events-none absolute left-0 top-0 hidden h-4 w-4 items-center justify-center rounded-sm bg-primary text-primary-foreground peer-checked:flex",
                    className
                )}>
                    <Check className="h-3 w-3 text-current" />
                </div>
                <div className="pointer-events-none absolute inset-0 rounded-sm border border-primary peer-checked:border-transparent"></div>
            </div>
        )
    }
)
Checkbox.displayName = "Checkbox"

export { Checkbox }
