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
 * Thrown when comparing two Paillier contexts and the contexts are not the same.
 */
public class PaillierContextMismatchException extends PaillierKeyMismatchException {

  private static final long serialVersionUID = -6169034734530199098L;

  /**
   * Constructs a new {@code PaillierContextMismatchException} without a specific message.
   */
  public PaillierContextMismatchException() {
    super();
  }

  /**
   * Constructs a new {@code PaillierContextMismatchException} with a specific message.
   * @param message the detail message.
   */
  public PaillierContextMismatchException(String message) {
    super(message);
  }

  /**
   * Constructs a new {@code PaillierContextMismatchException} with the exception cause.
   * @param cause the cause.
   */
  public PaillierContextMismatchException(Throwable cause) {
    super(cause);
  }

  /**
   * Constructs a new {@code PaillierContextMismatchException} with a specific message and the exception cause.
   * @param message the detail message,
   * @param cause the cause.
   */
  public PaillierContextMismatchException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Constructs a new {@code PaillierContextMismatchException} with a specific message and the exception cause.
   * @param message the detail message.
   * @param cause the cause.
   * @param enableSuppression whether suppression is enabled or disabled.
   * @param writableStackTrace whether the stack trace should be writable.
   */
  public PaillierContextMismatchException(String message, Throwable cause,
                                          boolean enableSuppression,
                                          boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
