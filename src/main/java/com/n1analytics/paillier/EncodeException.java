/**
 * Copyright 2015 NICTA
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.n1analytics.paillier;

/**
 * Thrown when an encoding operation fails.
 */
public class EncodeException extends PaillierRuntimeException {

  private static final long serialVersionUID = -8363238490528476897L;

  /**
   * Constructs a new {@code EncodeException} without a specific message.
   */
  public EncodeException() {
    super();
  }

  /**
   * Constructs a new {@code EncodeException} with a specific message.
   * @param message the detail message.
   */
  public EncodeException(String message) {
    super(message);
  }

  /**
   * Constructs a new {@code EncodeException} with the exception cause.
   * @param cause the cause.
   */
  public EncodeException(Throwable cause) {
    super(cause);
  }

  /**
   * Constructs a new {@code EncodeException} with a specific message and the exception cause.
   * @param message the detail message,
   * @param cause the cause.
   */
  public EncodeException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Constructs a new {@code EncodeException} with a specific message and the exception cause.
   * @param message the detail message.
   * @param cause the cause.
   * @param enableSuppression whether suppression is enabled or disabled.
   * @param writableStackTrace whether the stack trace should be writable.
   */
  public EncodeException(String message, Throwable cause, boolean enableSuppression,
                         boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
