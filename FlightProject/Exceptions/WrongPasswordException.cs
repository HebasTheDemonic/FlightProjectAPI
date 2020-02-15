using System;
using System.Runtime.Serialization;

namespace FlightProject.Exceptions
{
    [Serializable]
    public class WrongPasswordException : Exception
    {
        internal WrongPasswordException()
        {
        }

        internal WrongPasswordException(string message) : base(message)
        {
        }

        internal WrongPasswordException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected WrongPasswordException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}