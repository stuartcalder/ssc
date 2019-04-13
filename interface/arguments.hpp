#ifndef ARGUMENTS_HPP
#define ARGUMENTS_HPP

bool sanitize_arguments(const char **arguments,
                        const char **allowed_args,
                        const int num_args,
                        const int num_allowed_args);

#endif
