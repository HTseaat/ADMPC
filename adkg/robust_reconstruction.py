from adkg.polynomial import polynomials_over
from adkg.reed_solomon import (
    Algorithm,
    EncoderFactory,
    DecoderFactory,
    RobustDecoderFactory,
)
from adkg.reed_solomon import IncrementalDecoder

# TODO: Abstract this to a separate file instead of importing it from here.
from adkg.batch_reconstruction import fetch_one


async def robust_reconstruct(field_futures, field, n, t, point, degree):
    use_omega_powers = point.use_omega_powers
    enc = EncoderFactory.get(
        point, Algorithm.FFT if use_omega_powers else Algorithm.VANDERMONDE
    )
    dec = DecoderFactory.get(
        point, Algorithm.FFT if use_omega_powers else Algorithm.VANDERMONDE
    )
    robust_dec = RobustDecoderFactory.get(t, point, algorithm=Algorithm.GAO)
    incremental_decoder = IncrementalDecoder(enc, dec, robust_dec, degree, 1, t)

    async for (idx, d) in fetch_one(field_futures):
        print(f"idx: {idx}, d.value: {d.value}")
        print(f"type idx: {type(idx)}")
        print(f"type d.value: {type(d.value)}")
        incremental_decoder.add(idx, [d.value])
        
        if incremental_decoder.done():
            polys, errors = incremental_decoder.get_results()
            return polynomials_over(field)(polys[0]), errors
    return None, None

async def robust_reconstruct_admpc(shares_list, key_proposal, field, t, point, degree):
    use_omega_powers = point.use_omega_powers
    enc = EncoderFactory.get(
        point, Algorithm.FFT if use_omega_powers else Algorithm.VANDERMONDE
    )
    dec = DecoderFactory.get(
        point, Algorithm.FFT if use_omega_powers else Algorithm.VANDERMONDE
    )
    robust_dec = RobustDecoderFactory.get(t, point, algorithm=Algorithm.GAO)
    incremental_decoder = IncrementalDecoder(enc, dec, robust_dec, degree, 1, t)

    for i in range(len(shares_list)):
        if i in key_proposal: 
            incremental_decoder.add(i, [shares_list[i]])

        if incremental_decoder.done(): 
            polys, errors = incremental_decoder.get_results()
            return polynomials_over(field)(polys[0]), errors
    
    return None, None

async def robust_rec_admpc(shares_list, key_proposal, field, t, point, degree):
    use_omega_powers = point.use_omega_powers
    enc = EncoderFactory.get(
        point, Algorithm.FFT if use_omega_powers else Algorithm.VANDERMONDE
    )
    dec = DecoderFactory.get(
        point, Algorithm.FFT if use_omega_powers else Algorithm.VANDERMONDE
    )
    robust_dec = RobustDecoderFactory.get(t, point, algorithm=Algorithm.GAO)
    incremental_decoder = IncrementalDecoder(enc, dec, robust_dec, degree, 1, t)

    for i in range(len(shares_list)):

        incremental_decoder.add(key_proposal[i], [shares_list[i]])

        if incremental_decoder.done(): 
            polys, errors = incremental_decoder.get_results()
            return polynomials_over(field)(polys[0]), errors
    
    return None, None