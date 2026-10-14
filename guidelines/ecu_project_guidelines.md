# ECU project coding guidelines (organisation-specific, approved source)

## ICR-P01 CAN receive buffers
Every CAN receive handler must validate the DLC / payload length against the destination buffer size before copying payload bytes. Copy loops over receive buffers must use the buffer length constant with a strict '<' bound.

## ICR-P02 Diagnostic security keys and seeds
Security-access keys, seeds and authentication secrets must come from the HSM or secure storage. They must never appear as string literals in source, and seeds must come from the hardware TRNG, not rand().

## ICR-P03 Deviations
A rule deviation is recorded inline as `scr-ignore <RULE-ID>: <reason>` on the same or previous line and must be approved by the technical lead in the review tool.

## ICR-P04 Memory and stack
No dynamic memory after initialisation, no recursion, and every function must have a statically known worst-case stack usage.

## ICR-P05 Logging
Log functions take constant format strings. Never pass received CAN or diagnostic data as the format argument.
