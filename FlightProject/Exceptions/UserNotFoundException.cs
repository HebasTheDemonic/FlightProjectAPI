using System;
using System.Runtime.Serialization;

namespace FlightProject.Exceptions
{
    [Serializable]
    public class UserNotFoundException : Exception
    {
        internal UserNotFoundException()
        {
        }

        internal UserNotFoundException(string message) : base(message)
        {
        }

        internal UserNotFoundException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected UserNotFoundException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}